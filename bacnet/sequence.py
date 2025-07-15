import bacnet.enum as enums
import bacnet.bitstring as bitstrings
#sequence for different property
# A sequence is represented by a tuple containing a context and a fiedl_sequence
#   the context is represented by a disct Int -> e,
#       It serve to decode correctly the object depending on its context tag
#   the field sequence is represented by a list(f)
#       It serve to decode correctly the object depending it index in the sequence


class e:
    def __init__(self, ctx_type, field : str, enum : dict=None, bitstring : dict= None):
        '''Ctxt entry representing an entry in a sequence with a field name a context and possibly an enum/bitstring'''

        self.ctx_type = ctx_type
        self.field = field
        self.enum = enum
        self.bitstring = bitstring
        
class f:
    '''Field entry representing an entry in a sequence with a fiedl name and possibly an enum/bitstring'''
    def __init__(self, field : str, enum : dict=None, bitstring : dict= None):
        self.field = field
        self.enum = enum
        self.bitstring = bitstring


date_time = ({},[])

to_event= ({},[
    f("TO_OFFNORMAL"),
    f("TO_FAULT"),
    f("TO_NORMAL")
])

priority = ({},[
    f("TO_OFFNORMAL"),
    f("TO_FAULT"),
    f("TO_NORMAL")
])

date_range = ({},[
    f("start-date"),
    f("end-date")
])

property_ref = ({
    0 : e("Enumerated", "property-id", enum=enums.property_identifier_enum),
    1 : e("UnsignedInt", "property-array-index")
},[])

device_object_property_ref = ({
    0 : e("Identifier",  "object-identifier"),
    1 : e("Enumerated",  "property-identifier", enum=enums.property_identifier_enum),
    2 : e("UnsignedInt", "property-array-index"),
    3 : e("Identifier",  "device-identifier")
},[])

device_object_property_value = ({
    0 : e("Identifier",  "device-identifier"),
    1 : e("Identifier",  "object-identifier"),
    2 : e("Enumerated",  "property-identifier", enum=enums.property_identifier_enum),
    3 : e("UnsignedInt", "property-array-index"),
    4 : e(({},[]),  "property-value")
},[])

time_stamp = ({
    0 : e("Time","time"),
    1 : e("UnsignedInt", "sequence_number"),
    2 : e("DateTime","datetime") 
},[])

event_time_stamps = (
    time_stamp[0],
    to_event[1])

host_address = ({
    0 : e("Null","none"),
    1 : e("OctetString","ip-address"),
    2 : e("CharString", "name")
},[])

host_n_port = ({
    0 : e(host_address,"host"),
    1 : e("UnsignedInt","port")
},[])

BDT_entry = ({
    0 : e(host_n_port,"bbmd-address"),
    1 : e("OctetString","broadcast-mask")
},[])

shed_level = ({
    0 : e("UnsignedInt","percent"),
    1 : e("UnsignedInt", "level"),
    2 : e("Real", "amount")
},[])

lighting_command = ({
    0 : e("Enumerated", "opertion", enum=enums.lighting_operation),
    1 : e("Real", "target-level"),
    2 : e("Real", "ramp_rate"),
    3 : e("Real", "step-increment"),
    4 : e("UnsignedInt", "fade-time"),
    5 : e("UnsignedInt", "priority")
},[])

calendar_entry = ({
    0 : e("Date", "date"),
    1 : e( date_range, "date-range"),
    2 : e("OctetString", "weekNDay")
},[])

time_value = ({},[
    f("time"),
    f("value")
])

special_event = ({
    0 : e(calendar_entry, "calendar-entry"),
    1 : e("Identifier", "calendar-reference"),
    2 : e(time_value, "list-of-time-values"),
    3 : e("UnsignedInt", "event-priority")
},[])

device_object_reference = ({
    0 : e("Identifier", "device-identifier"),
    1 : e("Identifier", "object-identifier")
},[])

scale = ({
     0: e("Real","float-scale"),
     1: e("SignedInt", "integer-scale")
},[])

action_command = ({
    0 : e("Identifier", "device-identifier"),
    1 : e("Identifier", "object-identifier"),
    2 : e("Enumerated", "property-identifier", enum=enums.property_identifier_enum),
    3 : e("UnsignedInt", "property-array-index"),
    4 : e(({},[]), "property-value"),
    5 : e("UnsignedInt", "priority"),
    6 : e("UnsignedInt", "post-delay"),
    7 : e("Bool", "quit-on-failure"),
    8 : e("Bool", "write-successful"),
},[])


address = ({},[
    f("network-number"),
    f("mac-address")
])

address_binding = ({},[
    f("device-identifier"),
    f("device-address")
    ]
)


recipient = ({
    0 : e("Identifier", "recipient"),
    1 : e( address , "address")
},[])

destination = (recipient[0],[
    f("valid-days", bitstring=bitstrings.days_of_week_bs),
    f("from-time"),
    f("to-time"),
    f("recipient"),
    f("process-id"),
    f("issue-confirmed-notifications"),
    f("transitions", bitstring=bitstrings.event_transition_bs)

])

object_property_ref = ({
    0 : e("Identifier",  "object-identifier"),
    1 : e("Enumerated",  "property-identifier", enum=enums.property_identifier_enum),
    2 : e("UnsignedInt", "property-array-index"),
},[])

value_source = ({
    0 : e("Null", "none"),
    1 : e( device_object_reference, "object"),
    2 : e(address, "address")
},[])

name_value = ({
    0 : e("CharString","name")
},[])

name_value_collection = ({
    0 : e("CharString","members")
},[])

access_rule = ({
    0 : e("Enumerated", "time-range-specifier", enum=enums.specifier),
    1 : e( device_object_property_ref, "time-range"),
    2 : e("Enumerated", "location_specfier", enum=enums.specifier),
    3 : e( device_object_reference, "location"),
    4 : e("Bool", "enable")
},[])

assigned_access_rights = ({
    0 : e(device_object_reference, "assigned-access-right"),
    1 : e("Bool", "enable")
},[])

assigned_landing_calls = ({
    0 : e("UnsignedInt", "floor-number"),
    1 : e("Bool", "direction")
},[])

accumulator_record = ({
    0 : e( date_time, "timestamp"),
    1 : e("UnsignedInt", "present-value"),
    2 : e("UnsignedInt", "accumulator-value"),
    3 : e( "Enumerated", "accumulator-status", enum=enums.accumulator_status),
},[])

audit_notification = ({
    0 : e( time_stamp, "source-timestamp"),
    1 : e( time_stamp, "target-timestamp"),
    2 : e( recipient, "source-device"),
    3 : e( "Identifier", "source-object"),
    4 : e( "Enumerated", "operation", enum=enums.audit_operation),
    5 : e( "CharString", "source-comment" ),
    6 : e( "CharString", "target-comment" ),
    7 : e( "UnsignedInt", "invoke-id"),
    8 : e( "UnsignedInt", "source-user-id"),
    9 : e( "UnsignedInt", "source-user-tole"),
    10: e( recipient, "target-device"),
    11: e( "Identifier", "target-object"),
    12: e( property_ref, "target-property"),
    13: e( "UnsignedInt", "target-priority"),
    14: e( ({},[]), "target-value"),
    15: e( ({},[]), "current-value"),
    16: e( ({},[]), "error")
},[])



log_datum = ({
    0 : e( "BitString", "log-status", bitstring=bitstrings.log_status_bs),
    1 : e(  audit_notification, "audit-notification"),
    2 : e( "Real", "time-change")
},[])

audit_log_record = ({
    0 : e( date_time, "timestamp"),
    1 : e( log_datum, "log-datum"),
},[])


audit_log_record_result = ({
    0 : e( "UnsignedInt", "sequence-number"),
    1 : e( audit_log_record, "log-record"),
},[])



authentication_factor = ({
    0 : e("Enumerated", "format-type", enum=enums.authentication_factor_type),
    1 : e("UnsignedInt", "format-class"),
    2 : e("OctetString", "value" )
},[])

authentication_factor_format = ({
    0 : e("Enumerated", "format-type", enum=enums.authentication_factor_type),
    1 : e("UnsignedInt", "vendor-id"),
    2 : e("UnsignedInt", "vendor-format"),
},[])

policy = ({
    0 : e(device_object_reference, "credential-data-input"),
    1 : e("UnsignedInt", "index")
},[])

authentication_policy = ({
    0 : e(policy, "policy"),
    1 : e("Bool", "order-enforced"),
    2 : e("UnsignedInt", "timeout"),
},[])

channel_value = ({
    0 : e(lighting_command ,"")
},[])


list_of_cov_references = ({
    0 : e(property_ref, "monitored-property"),
    1 : e("Real", "cov-increment"),
    2 : e("Bool", "timestamped")
},[])

list_of_cov_subscription_specifications= ({
    0 : e("Identifier", "monitored-object-identifier"),
    1 : e(list_of_cov_references, "list-of-cov-references"),
},[])

recipient_process = ({
    0 : e(recipient , "recipient"),
    1 : e("UnsignedInt", "process-identifier")
},[])

cov_multiple_subscription = ({
    0 : e(recipient_process, "recipient"),
    1 : e("Bool", "issue-confirmed-notifications"),
    2 : e("UnsignedInt", "time-remaining"),
    3 : e("UnsignedInt", "max-notification-delay"),
    4 : e( list_of_cov_subscription_specifications, "list-of-cov-subscription-specifications")
},[])

cov_subscription = ({
    0 : e(recipient_process, "recipient"),
    1 : e( object_property_ref, "monitored-property-reference"),
    2 : e("Bool", "issue-confirmed-notifications"),
    3 : e("UnsignedInt", "time-remaining"),
    4 : e("Real", "cov-increment"),
},[])

credential_authentication_factor = ({
    0 : e("Enumerated", "disable", enum=enums.access_authentication_factor_disable),
    1 : e( authentication_factor, "authentication-factor"),
},[])

log_datum = ({
    0 : e( "BitString", "log-status", bitstring=bitstrings.log_status_bs),
    1 : e(  ({},[]), "notification"),
    2 : e( "Real", "time-change")
},[])

event_log_record = ({
    0 : e(date_time, "timestamp"),
    1 : e( log_datum, "log-datum"),
},[])

event_notification_subscription = ({
    0 : e( recipient, "recipient"),
    1 : e( "UnsignedInt", "process-identifier"),
    2 : e( "Bool", "issue-confirmed-notifications"),
    3 : e( "UnsignedInt", "time-remaining")
},[])



fdt_entry = ({
    0 : e("OctetString", "baacnetip-address"),
    1 : e( "UnsignedInt", "time-to-live"),
    2 : e( "UnsignedInt", "remaining-time-to-live"),
},[])

landing_call_command =({
    0 : e("Enumerated", "direction", enum=enums.lift_car_direction),
    1 : e( "UnsignedInt", "destination"),
},[])

landing_call_status = ({
    0 : e("UnsignedInt", "floor-number"),
    1 : e( landing_call_command, "command"),
    2 : e( "CharString", "floor-text"),
},[])

landing_door_status = ({
    0 : e("UnsignedInt", "floor-number"),
    1 : e( "Enumerated", "door-status", enum=enums.door_status),
},[])


lift_car_call_list = ({
    0 : e("UnsignedInt", "floor-numbers"),
},[])

log_data_in = ({
    0 : e( "Bool", "boolean-value"),
    1 : e( "Real", "real-value"),
    2 : e( "Enumerated", "enumerated-value"),
    3 : e( "UnsignedInt", "unsigned-value"),
    4 : e( "SignedInt", "integer-value" ),
    5 : e( "BitString", "bitstring-value" ),
    6 : e( "Null", "null-value" ),
    7 : e( ({},[]), "error"),
    8 : e( ({},[]), "any-value"),
},[])


log_data = ({
    0 : e( "BitString", "log-status", bitstring=bitstrings.log_status_bs),
    1 : e( log_data_in, "log-data"),
    3 : e( "Real", "time-change")
},[])

log_multiple_record = ({
    0 : e( date_time, "timestamp"),
    1 : e( log_data, "log-data"),
},[])


log_datum = ({
    0 : e( "BitString","log-status", bitstring=bitstrings.log_status_bs),
    1 : e( "Bool", "boolean-value"),
    2 : e( "Real", "real-value"),
    3 : e( "Enumerated", "enumerated-value"),
    4 : e( "UnsignedInt", "unsigned-value"),
    5 : e( "SignedInt", "integer-value" ),
    6 : e( "BitString", "bitstring-value" ),
    7 : e( "Null", "null-value" ),
    8 : e( ({},[]), "error"),
    9 : e( "Real", "time-change"),
    10: e( ({},[]), "any-value"),
},[])

log_record = ({
    0 : e( date_time, "timestamp"),
    1 : e( log_datum, "log-datum"),
    2 : e( "BitString","status-flags", bitstring=bitstrings.status_flags_bs)
},[])

object_selector =  ({
    0 : e( "Null", "none"),
    1 : e( "Identifier", "objet"),
    2 : e( "Enumerated","object-type",enum=enums.object_types)
},[])

port_permission = ({
    0 : e( "UnsignedInt", "port-id"),
    1 : e( "Bool", "enabled"),
},[])

prescale = ({
    0 : e( "UnsignedInt", "multiplier"),
    1 : e( "UnsignedInt", "moodulo-divide"),
},[])

priority_value = ({
    0 : e( ({},[]), "constructed-value"),
    1 : e( date_time, "datetime"),
},[])

property_access_result = ({
    0 : e("Identifier",  "object-identifier"),
    1 : e("Enumerated",  "property-identifier", enum=enums.property_identifier_enum),
    2 : e("UnsignedInt", "property-array-index"),
    3 : e("Identifier",  "device-identifier"),
    4 : e( ({},[]), "property-value"),
    5 : e( ({},[]), "property-access-error"),
},[])


router_entry = ({
    0 : e("UnsignedInt",  "network-number"),
    1 : e("OctetString",  "mac-address"),
    2 : e("Enumerated", "status", enum= {
        0 : "avaible",
        1 : "busy",
        2 : "disconected"
    }),
    3 : e("UnsignedInt",  "performance-index"),
},[])

set_point_reference = ({
    0 : e( object_property_ref,  "setpoint-reference"),
},[])

stage_limit_value = ({},[
    f("limit"),
    f("values"),
    f("deadband")
])

timer_state_change_value = ({
    0 : e( "Null",  "no-value"),
    1 : e(({},[]) , "constructed-value"),
    2 : e( date_time , "datetime"),
    3 : e( lighting_command, "lighting-command")
},[])

vmac_entry = ({
    0 : e( "OctetString",  "virtual-mac-address"),
    1 : e( "OctetString",  "native-mac-address"),
},[])

vt_session = ({},[
    f("local-vt-session-id"),
    f("remote-vt-session-id"),
    f("remote-vt-address")
])

property_states= ({
    0 : e( "Bool", "boolean-value"),
    1 : e("Enumerated", "binary-value", enum=enums.binary_pv),
    2 : e("Enumerated", "event-type", enum=enums.event_type),
    3 : e("Enumerated", "polarity", enum=enums.polarity),
    4 : e("Enumerated", "program-change", enum=enums.program_request),
    5 : e("Enumerated", "progra,-state", enum=enums.program_state),
    6 : e("Enumerated", "reaason-for-halt", enum=enums.program_error),
    7 : e("Enumerated", "reliability", enum=enums.reliability),
    8 : e("Enumerated", "state", enum=enums.event_state),
    9 : e("Enumerated", "system-status", enum=enums.device_status),
    10: e("Enumerated", "units", enum=enums.engineering_units),
    11: e("UnsignedInt", "unsigned-value"),
    12: e("Enumerated", "life-safety-mode", enum=enums.lifesafety_mode),
    13: e("Enumerated", "life-safety-state", enum=enums.lifesafety_state),
    14: e("Enumerated", "restart-reason-mode", enum=enums.restart_reason),
    15: e("Enumerated", "door-alarm-state", enum=enums.door_alarm_state),
    16: e("Enumerated", "action", enum=enums.action),
    17: e("Enumerated", "door-secured-status", enum=enums.door_secured_status),
    18: e("Enumerated", "door-statuse", enum=enums.door_status),
    19: e("Enumerated", "door-value", enum=enums.door_value),
    20: e("Enumerated", "file.access-amethod", enum=enums.file_access_method),
    21: e("Enumerated", "lock-status", enum=enums.lock_status),
    22: e("Enumerated", "life-safety-operation", enum=enums.lifesafety_operation),
    23: e("Enumerated", "maintenance", enum=enums.maintenance),
    24: e("Enumerated", "node-type", enum=enums.node_type),
    25: e("Enumerated", "notify-type", enum=enums.notify_type),

    27: e("Enumerated", "shed-state", enum=enums.shed_state),
    28: e("Enumerated", "silenced-state", enum=enums.silence_state),

    30: e("Enumerated", "access-event", enum=enums.access_event),
    31: e("Enumerated", "zone-occupancy-state", enum=enums.access_zone_occupancy_state),
    32: e("Enumerated", "access-credential-disable-reason", enum=enums.access_credential_disable_reason),
    33: e("Enumerated", "access-credential-disable", enum=enums.access_credential_disable),
    34: e("Enumerated", "authentication-status", enum=enums.authentication_status),
    36: e("Enumerated", "backup-state", enum=enums.backup_state),
    37: e("Enumerated", "write-status", enum=enums.write_status),
    38: e("Enumerated", "lighting-in-progress", enum=enums.lighting_in_progress),
    39: e("Enumerated", "lighting-operation", enum=enums.lighting_operation),
    40: e("Enumerated", "lighting-transition", enum=enums.lighting_transition),
    41: e("SignedInteger", "integer-value"),
    42: e("Enumerated", "binary-lighting-value", enum=enums.binary_lighting_pv),
    43: e("Enumerated", "time-state", enum=enums.timer_state),
    44: e("Enumerated", "timer-transition", enum=enums.timer_transition),
    45: e("Enumerated", "ip-mode", enum=enums.ip_mode),
    46: e("Enumerated", "network-port-command", enum=enums.network_port_command),
    47: e("Enumerated", "network-type", enum=enums.network_type),
    48: e("Enumerated", "network-number-quality", enum=enums.network_number_quality),
    49: e("Enumerated", "escalator-operation-direction", enum=enums.escalator_operation_direction),
    50: e("Enumerated", "escalator-fault", enum=enums.escalator_fault),
    51: e("Enumerated", "escalator-mode", enum=enums.escalator_mode),
    52: e("Enumerated", "lift-car-direction", enum=enums.lift_car_direction),
    53: e("Enumerated", "lift-car-door-command", enum=enums.lift_car_door_command),
    54: e("Enumerated", "lift-car-drive-status", enum=enums.lift_car_drive_status),
    55: e("Enumerated", "lift-car-mode", enum=enums.lift_car_mode),
    56: e("Enumerated", "lift-group-mode", enum=enums.lift_group_mode),
    57: e("Enumerated", "lift-fault", enum=enums.lift_fault),
    58: e("Enumerated", "protocol-level", enum=enums.protocol_level),
    59: e("Enumerated", "audit-level", enum=enums.audit_level),
    60: e("Enumerated", "audit-operation", enum=enums.audit_operation),
    58: e("UnsignedInt", "extended-value"),
#...
},[])

event_parameter = ({
    0 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("BitString", "bitmask"),
            2 : e("BitString" , "list-of-bitsting-values")
        },[]),"change-of-bitstring"),
    1 : e ( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e( property_states, "list-of-values")
        },()), "change-of-state"),
    2 :   e (({
            0 : e("UnsignedInt", "time-delay"),
            1 : e( ({
                    0 : e("BitString", "bit-mask"),
                    1 : e("Real", "referencec-property-increment")
                },[]),"cov-criteria")
        },[]),"change-of-value"),
    3 : e(({
            0 : e("UnsignedInt", "time-delay"),
            1 : e( object_property_ref, "feedback-property-reference")
        },[]), "command-failure"),
    4 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e( object_property_ref, "feedback-property-reference"),
            2 : e("Real", "low-diff-limit"),
            3 : e("Real", "high-diff-limit"),
            4 : e("Real", "deadband")
        },[]), "floating-limit"),
    5 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("Real", "low-diff-limit"),
            2 : e("Real", "high-diff-limit"),
            3 : e("Real", "deadband")
        },[]), "out-of-range"),
    8 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("Enumerated", "list-of-life-safety-alarm-values", enum=enums.lifesafety_state),
            2 : e("Enumerated", "list-of-alarm-values", enum=enums.lifesafety_state),
            3 : e(device_object_property_ref, "mode-property-reference")
        },[]), "change-of-life-safety"),
    9 : e( ({
            0 : e("UnsignedInt", "vendor-id"),
            1 : e("UnsignedInt", "extended-event-type"),
            2 : e( ({
                0 : (device_object_property_ref, "reference")
            },[]), "parameters")
        },[]), "extended"),
   10 : e( ({
            0 : e("UnsignedInt", "notification-threshold"),
            1 : e("UnsignedInt", "previous-notification-count"),
        },[]), "buffer-ready"),
    11 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("UnsignedInt", "low-limit"),
            2 : e("UnsignedInt", "high-limit"),
        },[]), "unsigned-range"),
    13 : e( ({
            0 : e("Enumerated", "list-of-access-events", enum=enums.access_event),
            1 : e( device_object_property_ref, "access-event-time.reference"),
        },[]), "access-event"),
    14 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("Real", "low-limit"),
            2 : e("Real", "high-limit"),
            3 : e("Real", "deadband"),
        },[]), "double-out-of-range"),
    15 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("SignedInt", "low-limit"),
            2 : e("SignedInt", "high-limit"),
            3 : e("UnsignedInt", "deadband"),
        },[]), "signed-out-of-range"),
    16 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("UnsignedInt", "low-limit"),
            2 : e("UnsignedInt", "high-limit"),
            3 : e("UnsignedInt", "deadband"),
        },[]), "unsigned-out-of-range"),
    17 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("CharString", "list-of-alarm-values-limit"),
        },[]), "change-of-charaxterstring"),
    18 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("Enumerated", "selected-flags", enum=enums.status_flags),
        },[]), "change-of-status-flags"),
    20 : e("Null", "None"),
    21 : e( ({
            0 : e("UnsignedInt", "time-delay"),
        },[]), "change-of-discrete-value"),
    22 : e( ({
            0 : e("UnsignedInt", "time-delay"),
            1 : e("Enumerated", "alarm-values", enum=enums.timer_state),
            2 : e(device_object_property_ref, "update-time-reference")
        },[]), "change-of-timer"),
},[])

fault_parameter = ({
    0 : e("Null","None"),
    1 :e(({
            0 : e("CharString","list-of-fault-values")
        },[]),"fault-characterstring"),
    2 : e(({
            0 : e("UnsignedInt", "vendor-id"),
            1 : e("UnsignedInt", "extended-fault-type"),
            2 : e( ({
                0 : (device_object_property_ref, "reference")
            },[]), "parameters")
        },[]),"fault-extended"),
    3 : e(({
            0 : e("Enumerated", "list-of-fault-values", enum=enums.lifesafety_state),
            1 : e(device_object_property_ref, "mode-property-reference")
        },[]), "fault-life-safety"),
    4 : e(({
            0 : e(property_states,"list-of-fault-values")
        },[]), "fault-state"),
    5 : e(({
            0 : e(device_object_property_ref,"status-flag-reference")
        },[]), "fault-status-flag"),
    6 : e(({
            0 : e(({},[]),"min-normal-value"),
            1 : e(({},[]),"max-normal-value")
        },[]), "fault-out-of-rang"),
    7 : e(({
            0 : e(device_object_property_ref,"fault-listed-reference")
        },[]), "fault-listed"),
},[])


notification_parameters = ({},[]) #TODO


context_by_property = {
    "log-device-object-property" : device_object_property_ref,
    "list-of-object-property-references" : device_object_property_ref,
    "last-command-time": time_stamp,
    "command-time-array": time_stamp,
    "last-restore-time": time_stamp,
    "time-of-device-restart": time_stamp,
    "access-event-time": time_stamp,
    "update-time": time_stamp,
    "bbmd-broadcast-distribution-table": BDT_entry,
    "bacnet-ip-global-address" : host_n_port,
    "fd-bbmd-address" : host_n_port,
    "requested-shed-level" : shed_level,
    "expected-shed-level" : shed_level,
    "actual-shed-level" : shed_level,
    "lighting-command" : lighting_command,
    "exception-schedule" : special_event,
    "event-time-stamps" : event_time_stamps,
    "event-message-texts" : to_event,
    "event-message-texts-config" : to_event,
    "priority" : priority,
    "member-of" : device_object_reference,
    "zone-members" : device_object_reference,
    "door-members" : device_object_reference,
    "subordinate-list" : device_object_reference,
    "represents" : device_object_reference,
    "access-event-credential" : device_object_reference,
    "access-event-authentication-factor" :authentication_factor,
    "access-doors" : device_object_reference,
    "zone-to" : device_object_reference,
    "zone-from" :  device_object_reference,
    "credentials" : device_object_reference,
    "credentials-in-zone" : device_object_reference,
    "last-credential-added" : device_object_reference,
    "last-credential-removed" : device_object_reference,
    "entry-points" : device_object_reference,
    "exit-points" : device_object_reference,
    "members" : device_object_reference,
    "accompaniment" : device_object_reference,
    "belongs-to" :device_object_reference,
    "last-access-point":device_object_reference,
    "energy-meter-ref":device_object_reference,
    "target-references":device_object_reference,
    "scale" : scale,
    "action" : action_command,
    "recipient-list" : destination,
    "audit-notification-recipient" : recipient,
    "covu-recipients" : recipient,
    "utc-time-synchronization-recipients" : recipient,
    "restart-notification-recipients" : recipient,
    "time-synchronization-recipients" : recipient,
    "event-algorithm-inhibit-ref" : object_property_ref,
    "manipulate-variable-reference": object_property_ref,
    "input-reference" : object_property_ref,
    "value-source" : value_source,
    "value-source-array" : value_source,
    "tags" :  name_value,
    "negative-access-rules" : access_rule,
    "positive-access-rules" : access_rule,
    "logging-record" : accumulator_record,
    "device-address-binding" : address_binding,
    "manunal-slave-address-binding" : address_binding,
    "assigned-access-rights" : assigned_access_rights,
    "assigned-landing-calls" : assigned_landing_calls,
    "supported-formats" : authentication_factor_format,
    "authentication-policy-list" : authentication_policy,
    #"active-cov-multiple-subscriptions":cov_multiple_subscription,
    "active-cov-subscriptions":cov_subscription,
    "authentication-factors" : credential_authentication_factor,
    "weekly-schedule" : time_value,
    "subscribed-recipients" : event_notification_subscription,
    "bbmd-foreign-device-table" : fdt_entry,
    "landing-calls" : landing_call_status,
    "landing-calls-control" : landing_call_status,
    "landing-door-status" : landing_door_status,
    "registered-car-call" : lift_car_call_list,
    "subordinate-tags" : name_value_collection,
    "monitored-objects" : object_selector,
    "port-filter" : port_permission,
    "prescale" : prescale,
    "priority-array" : priority_value,
    "routing-table" : router_entry,
    "setpoint-reference" : set_point_reference,
    "stages" : stage_limit_value,
    "state-change-values" : timer_state_change_value,
    "virtual-mac-address-table" : vmac_entry,
    "active-vt-sessions" : vt_session,
    "controlled-variable-reference" : object_property_ref,
    "manipulated-variable-reference" : object_property_ref,
    "fault-parameters" : fault_parameter,
    "event-parameters" :  event_parameter
    
    }


present_value_type = {
    "credential-data-input" : authentication_factor,
    "channel" : channel_value,
    "global-group" : property_access_result,
}

log_buffer_type = {
    "trend-log-multiple" : log_multiple_record,
    "event-log" : event_log_record,
    "audit-log" : audit_log_record,
    "trend-log" : log_record
}


def get_ctxt_by_property_and_object(prop : str, obj_type : str):
    """
    Retrieves the context mapping for a given property and object type.

    :param prop: The property name
    :param obj_type: The object type
    :return: A tuple containing a dictionary and a list representing the context.
    """
    if prop == "log-buffer":
        return log_buffer_type.get(obj_type,({},[]))
    elif prop == "present-value":
        return present_value_type.get(obj_type,({},[]))
    else:
        return context_by_property.get(prop,({},[]))