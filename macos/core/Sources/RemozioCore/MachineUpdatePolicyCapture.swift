import Foundation

/// One protected account policy. Capturing it grants no activation or journal writer authority.
struct MachineUpdatePolicyCapture {
    let accountID: Data
    let snapshot: AuthorityCodePolicySnapshot?
}
