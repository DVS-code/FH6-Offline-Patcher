from formatter_variant import discover_formatter_variant
from debugger_detach import discover_additional_detach_queries
from import_context import (discover_computer_name_result, discover_fatal_handler_debugger_call,
                            discover_webcall_cancellation)
from mac_collection import discover_mac_collector
from patch_actions import (clear_mutex_result_slots, entry_return, force_branch,
                           skip_debugger_detach_transaction, skip_reserved_identity_strike,
                           suppress_call, stall_entry, thread_hide_leaf_return)
from recognition import discover_profile
from role_validation import validate_region_shape
from response_creators import discover_response_creators
from rtti import discover_fatal_license_thunk
from static_container import ContainerError


def encode_reviewed_action(image, profile, rva):
    if profile.action in ("return_zero", "return_void", "return_true_bool"):
        return entry_return(image, profile.role, rva, profile.action.removeprefix("return_"))
    if profile.action == "suppress_call_zero":
        return suppress_call(image, profile.role, rva, zero_result=True)
    actions = {"force_branch": force_branch, "clear_mutex_slots": clear_mutex_result_slots,
               "stall_terminal_response": stall_entry,
               "return_from_thread_hide_leaf": thread_hide_leaf_return,
               "skip_reserved_identity_strike": skip_reserved_identity_strike,
               "skip_debugger_detach_transaction": skip_debugger_detach_transaction}
    if profile.action not in actions:
        raise ContainerError(f"Action has no completed proof: {profile.action}")
    return actions[profile.action](image, profile.role, rva)


def discover_reviewed_plan(image, profiles, *, require_region_validation=False):
    if not profiles or len({profile.role for profile in profiles}) != len(profiles):
        raise ContainerError("Missing or duplicate reviewed roles")
    patches, terminal, prototypes, detach = [], [], [], []
    for profile in profiles:
        if require_region_validation and profile.validation is None:
            raise ContainerError(f"{profile.role}: missing required complete-region validation")
        rva = discover_profile(image, profile)
        if profile.validation is not None:
            validate_region_shape(image, profile, rva, profile.validation)
        patches.append(encode_reviewed_action(image, profile, rva))
        if profile.action == "skip_debugger_detach_transaction":
            detach.append(patches[-1])
        if profile.action == "stall_terminal_response":
            terminal.append(rva)
        if "seven-argument decoded record" in profile.role:
            prototypes.append(rva)
    if len(terminal) != 1 or len(prototypes) != 1 or len(detach) != 1:
        raise ContainerError("Reviewed role metadata does not uniquely identify the required discovery roots")
    patches.append(discover_fatal_license_thunk(image))
    patches.extend(discover_response_creators(image, terminal[0]))
    patches.append(discover_formatter_variant(image, prototypes[0]))
    patches.append(discover_mac_collector(image))
    patches.append(discover_fatal_handler_debugger_call(image))
    patches.append(discover_computer_name_result(image))
    patches.append(discover_webcall_cancellation(image))
    patches.extend(discover_additional_detach_queries(image, detach[0]))
    return patches
