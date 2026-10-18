//! The rules about who may own and write what, as plain data: the descriptors of the folders and objects the client makes, and the verdict on a folder's owner and entries. `state` reads the real owners and entries from Windows and asks these.

/// SYSTEM and the Administrators group.
const TRUSTED: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];
/// What owns, and may write in, the folders of the system's own programs besides those two.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// CREATOR OWNER, whose entries are replaced by the owner's, and which is trusted exactly as far as the owner is.
const CREATOR_OWNER: &str = "S-1-3-0";
/// Write data or add a file, append data or add a subfolder, delete a child, delete, write the DACL, write the owner, and the generic write and all rights.
const WRITE_MASK: u32 = 0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;
/// Read and execute, which is what a folder that others may list and open gives.
const READ_EXECUTE: &str = "0x1200a9";

/// Who can reach a folder of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
	/// SYSTEM and administrators only.
	Private,
	/// Also users may list the folder itself, so that they can reach what is in a folder below it that is theirs to read.
	Traverse,
	/// Also users may read what is in the folder (the status of a connection holds no secret).
	Read,
}

/// The descriptor of a folder: the owner is the Administrators group, the DACL is protected so that a parent's entries do not flow in, and nobody else is named.
pub fn folder_sddl(access: Access) -> String {
	let users = match access {
		Access::Private => String::new(),
		Access::Traverse => format!("(A;;{READ_EXECUTE};;;BU)"),
		Access::Read => format!("(A;OICI;{READ_EXECUTE};;;BU)"),
	};
	format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){users}")
}

/// The descriptor of the lock's mutex and event: SYSTEM and administrators have everything and users can wait on them, which is what `veilway status` does. Only an administrator can set the event.
pub const OBJECT_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100000;;;BU)";

/// Whether the owner of a folder the client keeps its files in is one it can trust.
pub fn trusted_owner(sid: &str) -> bool {TRUSTED.contains(&sid)}

/// Whether the owner of the folder a program runs from is one it can trust: the system's installer owns Program Files.
pub fn trusted_install_owner(sid: &str) -> bool {trusted_owner(sid) || sid == TRUSTED_INSTALLER}

/// Whether an entry that allows `mask` to `sid` lets someone besides the trusted write in the folder it is on. An entry that is only inherited by what is inside does not apply to the folder.
pub fn grants_write(sid: &str, mask: u32, inherit_only: bool) -> bool {!inherit_only && mask & WRITE_MASK != 0 && !(trusted_install_owner(sid) || sid == CREATOR_OWNER)}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_folder_names_the_owner_a_protected_acl_and_users_only_as_far_as_asked() {
		let private = folder_sddl(Access::Private);
		assert!(private.starts_with("O:BAD:P") && !private.contains("BU"));
		assert!(folder_sddl(Access::Traverse).contains("(A;;0x1200a9;;;BU)"));
		assert!(folder_sddl(Access::Read).contains("(A;OICI;0x1200a9;;;BU)"));
	}

	#[test]
	fn only_system_and_administrators_own_the_client_folders() {
		assert!(trusted_owner("S-1-5-18") && trusted_owner("S-1-5-32-544"));
		assert!(!trusted_owner("S-1-5-21-1-2-3-1001") && !trusted_owner("S-1-5-32-545") && !trusted_install_owner("S-1-5-21-1-2-3-1001"));
		assert!(trusted_install_owner(TRUSTED_INSTALLER) && !trusted_owner(TRUSTED_INSTALLER));
	}

	#[test]
	fn an_untrusted_writer_of_the_exe_folder_is_found_and_a_reader_is_not() {
		assert!(grants_write("S-1-5-32-545", 0x2, false), "users may add files");
		assert!(grants_write("S-1-5-32-545", 0x1_0000, false), "users may delete");
		assert!(grants_write("S-1-5-11", 0x1f01ff, false), "authenticated users have full control");
		assert!(grants_write("S-1-5-21-1-2-3-1001", 0x4_0000, false), "write DACL");
		assert!(!grants_write("S-1-5-32-545", 0x1200a9, false), "users may read and execute");
		assert!(!grants_write("S-1-5-32-544", 0x1f01ff, false) && !grants_write("S-1-5-18", 0x1f01ff, false));
		assert!(!grants_write("S-1-5-32-545", 0x1f01ff, true), "inherit only does not apply to the folder");
	}
}
