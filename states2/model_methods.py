from django.utils import simplejson as json
from django.contrib.auth.models import User as Auth_user

from states2.exceptions import (PermissionDenied, TransitionCannotStart,
                                TransitionException, TransitionNotValidated,
                                UnknownTransition)
from states2.signals import before_state_execute, after_state_execute

import django.dispatch


def get_STATE_transitions(self, field='state'):
    '''
    Returns state transitions logs.

    :param str field: the name of the :class:`~states2.fields.StateField`
    '''
    if getattr(self, '_%s_log_model' % field, None):
        # Similar to: _state_log_model.objects.filter(on=self)
        return self.all_transitions.all()
    else:
        raise Exception('This model does not log state transitions. '
                        'Please enable it by setting log_transitions=True')


def get_public_STATE_transitions(self, field='state'):
    '''
    Returns the transitions which are meant to be seen by the customer.
    The admin on the other hand should be able to see everything.

    :param str field: the name of the :class:`~states2.fields.StateField`
    '''
    if getattr(self, '_%s_log_model' % field, None):
        transitions = getattr(self, 'get_%s_transitions' % field)
        return filter(lambda t: t.is_public and t.completed, transitions())
    else:
        return []


def get_STATE_machine(self, field='state', machine=None):
    '''
    Gets the machine

    :param str field: the name of the :class:`~states2.fields.StateField`
    :param states2.machine.StateMachine machine: the state machine, default
        ``None``
    '''
    return machine


def get_STATE_info(self, field='state', machine=None):
    '''
    Gets the state definition from the machine

    :param str field: the name of the :class:`~states2.fields.StateField`
    :param states2.machine.StateMachine machine: the state machine, default
        ``None``
    '''
    if machine is None:
        return None

    class state_info(object):
        '''
        An extra object that hijackes the actual state methods.
        '''
        @property
        def name(si_self):
            '''
            The name of the current state
            '''
            return getattr(self, field)

        @property
        def description(si_self):
            '''
            The description of the current state
            '''
            si = machine.get_state(getattr(self, field))
            return si.description

        @property
        def in_group(si_self):
            '''
            In what groups is this state? It's a dictionary that will return
            ``True`` for the state groups that this state is in.
            '''
            return machine.get_state_groups(getattr(self, field))

        def possible_transitions(si_self):
            '''
            Return list of transitions which can be made from the current
            state.
            '''
            for name in machine.transitions:
                t = machine.transitions[name]
                if getattr(self, field) in t.from_states:
                    yield t

        def test_transition(si_self, transition, user=None):
            '''
            Check whether we could execute this transition.

            :param str transition: the transition name
            :param user: the user that will execute the transition. Used for
                permission checking
            :type: :class:`django.contrib.auth.models.User` or ``None``

            :returns:``True`` when we expect this transition to be executed
                succesfully. It will raise an ``Exception`` when this
                transition is impossible or not allowed.
            '''
            # Transition name should be known
            if not machine.has_transition(transition):
                raise UnknownTransition(self, transition)

            t = machine.get_transitions(transition)

            if getattr(self, field) not in t.from_states:
                raise TransitionCannotStart(self, transition)

            # User should have permissions for this transition
            #if transition not implement the have_permission we give the permission
            #if they implment the method, call it and get the result
            #if they implement the method but no user given, raise the permission denied
            
            have_permission = False
            implemente_has_permission = getattr(t, 'has_permission', None)
            if implemente_has_permission and user:
               try:
                  have_permission = t.has_permission(self, user)
               except Exception, e:
                  #the have permission got an exception, probably because we call has_perm without user
                  pass
            elif implemente_has_permission and not user:
               have_permission = False
            else:
               have_permission = True
               
            if not have_permission:
               raise PermissionDenied(self, transition, user)
         

            # Transition should validate
            validation_errors = list(t.validate(self))
            if validation_errors:
                raise TransitionNotValidated(si_self, transition, validation_errors)

            return True

        def make_transition(si_self, transition, user=None, **kwargs):
            '''
            Executes state transition.

            :param str transition: the transition name
            :param user: the user that will execute the transition. Used for
                permission checking
            :type: :class:`django.contrib.auth.models.User` or ``None``
            :param dict kwargs: the kwargs that will be passed to
                :meth:`~states2.machine.StateTransition.handler`
            '''
            # Transition name should be known
            if not machine.has_transition(transition):
                raise UnknownTransition(self, transition)
            t = machine.get_transitions(transition)

            _state_log_model = getattr(self, '_%s_log_model' % field, None)

            # Start transition log
            if _state_log_model:
                # Try to serialize kwargs, for the log. Save null
                # when it's not serializable.
                try:
                    serialized_kwargs = json.dumps(kwargs)
                except TypeError:
                    serialized_kwargs = json.dumps(None)
                
                #we have to test if user is an instance of auth_user or a profile link to a user
                auth_user = user
                if user:
                   if not isinstance(user, Auth_user):
                      #user is not an auth_user, search the user.user and test instance
                      auth_user = getattr(user, 'user', None)
                      if auth_user and isinstance(auth_user, Auth_user):
                         auth_user = auth_user
                         #else let the exception raise
                
                transition_log = _state_log_model.objects.create(
                                on=self,
                                from_state=getattr(self, field),
                                to_state=t.to_state,
                                user=auth_user,
                                serialized_kwargs=serialized_kwargs,
                                )

            # Test transition (access/execution validation)
            try:
                si_self.test_transition(transition, user)
            except TransitionException, e:
                if _state_log_model:
                    transition_log.make_transition('fail')
                raise e

            # Execute
            if _state_log_model:
                transition_log.make_transition('start')

            try:
                from_state = getattr(self, field)

                before_state_execute.send(sender=self,
                                          from_state=from_state,
                                          to_state=t.to_state)
                # First call handler (handler should still see the original
                # state.)
                t.handler(self, user, **kwargs)

                # Then set new state and save.
                setattr(self, field, t.to_state)
                self.save()
                after_state_execute.send(sender=self,
                                         from_state=from_state,
                                         to_state=t.to_state)
            except Exception, e:
                if _state_log_model:
                    transition_log.make_transition('fail')

                # Print original traceback for debugging
                import traceback
                traceback.print_exc()
                raise e
            else:
                if _state_log_model:
                    transition_log.make_transition('complete')

                # *After completion*, call the handler of this state
                # definition
                machine.get_state(t.to_state).handler(self)

    return state_info()
