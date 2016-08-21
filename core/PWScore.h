/*
* Copyright (c) 2003-2016 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
#ifndef __PWSCORE_H
#define __PWSCORE_H

// PWScore.h
//-----------------------------------------------------------------------------

//#include "os/pws_tchar.h"
#include "StringX.h"
#include "PWSfile.h"
//#include "PWSFilters.h"
//#include "Report.h"
#include "Proxy.h"
#include "UIinterface.h"
//#include "Command.h"
//#include "CommandInterface.h"
//#include "DBCompareData.h"
//#include "ExpiredList.h"

#include "coredefs.h"

// Parameter list for ParseBaseEntryPWD
struct BaseEntryParms {
	// All fields except "InputType" are 'output'.
	StringX csPwdGroup;
	StringX csPwdTitle;
	StringX csPwdUser;
	pws_os::CUUID base_uuid;
	CItemData::EntryType InputType;
	CItemData::EntryType TargetType;
	int ibasedata;
	bool bMultipleEntriesFound;
	BaseEntryParms() : base_uuid(pws_os::CUUID::NullUUID()) {}
};

// Formatted Database properties
struct st_DBProperties {
	StringX database;
	StringX databaseformat;
	StringX numgroups;
	StringX numemptygroups;
	StringX numentries;
	StringX numattachments;
	StringX whenlastsaved;
	StringX wholastsaved;
	StringX whatlastsaved;
	StringX file_uuid;
	StringX unknownfields;
	StringX db_name;
	StringX db_description;
};

struct st_ValidateResults;

class PWScore
{
public:
	enum {
		SUCCESS = 0,
		FAILURE = 1,
		USER_DECLINED_SAVE = 2,
		CANT_GET_LOCK = 3,
		DB_HAS_CHANGED = 4,
		CANT_OPEN_FILE = PWSfile::CANT_OPEN_FILE, // -10
		USER_CANCEL = -9,                         // -9
		WRONG_PASSWORD = PWSfile::WRONG_PASSWORD, //  5
		BAD_DIGEST = PWSfile::BAD_DIGEST,         //  6
		TRUNCATED_FILE = PWSfile::TRUNCATED_FILE, //  8 (or maybe corrupt?)
		READ_FAIL = PWSfile::READ_FAIL,           //  9
		WRITE_FAIL = PWSfile::WRITE_FAIL,         //  10
		UNKNOWN_VERSION,                          //  11
		NOT_SUCCESS,                              //  12
		ALREADY_OPEN,                             //  13
		INVALID_FORMAT,                           //  14
		USER_EXIT,                                //  15
		XML_FAILED_VALIDATION,                    //  16
		XML_FAILED_IMPORT,                        //  17
		LIMIT_REACHED,                            //  18 - OBSOLETE (for demo)
		UNIMPLEMENTED,                            //  19
		NO_ENTRIES_EXPORTED,                      //  20
		DB_HAS_DUPLICATES,                        //  21
		OK_WITH_ERRORS,                           //  22
		OK_WITH_VALIDATION_ERRORS,                //  23
		OPEN_NODB                                 //  24
	};

	PWScore();
	~PWScore();

	bool SetUIInterFace(UIInterFace *pUIIF, size_t num_supported,
		std::bitset<UIInterFace::NUM_SUPPORTED> bsSupportedFunctions);

	// Clear out database structures and associated fields
	void ClearData();

	// Following used to read/write databases and Get/Set file name
	StringX GetCurFile() const { return m_currfile; }
	void SetCurFile(const StringX &file) { m_currfile = file; }

	int ReadCurFile(const StringX &passkey, const bool bValidate = false,
		const size_t iMAXCHARS = 0)
	{
		return ReadFile(m_currfile, passkey, bValidate, iMAXCHARS);
	}
	int ReadFile(const StringX &filename, const StringX &passkey,
		const bool bValidate = false, const size_t iMAXCHARS = 0);

	// R/O file status
	void SetReadOnly(bool state) { m_IsReadOnly = state; }
	bool IsReadOnly() const { return m_IsReadOnly; };

	// Check/Change master passphrase
	int CheckPasskey(const StringX &filename, const StringX &passkey);
	//void ChangePasskey(const StringX &newPasskey);
	void SetPassKey(const StringX &new_passkey);
	StringX GetPassKey() const; // returns cleartext - USE WITH CARE

	// Following used by SetPassKey
	void EncryptPassword(const unsigned char *plaintext, size_t len,
		unsigned char *ciphertext) const;

	// Access to individual entries in database
	ItemListIter GetEntryIter()
	{return m_pwlist.begin();}
	ItemListConstIter GetEntryIter() const
	{return m_pwlist.begin();}
	ItemListIter GetEntryEndIter()
	{return m_pwlist.end();}
	ItemListConstIter GetEntryEndIter() const
	{return m_pwlist.end();}
	CItemData &GetEntry(ItemListIter iter)
	{return iter->second;}
	const CItemData &GetEntry(ItemListConstIter iter) const
	{return iter->second;}
	ItemList::size_type GetNumEntries() const {return m_pwlist.size();}

	// Find in m_pwlist by group, title and user name, exact match
	ItemListIter Find(const StringX &a_group,
		const StringX &a_title, const StringX &a_user);
	ItemListIter Find(const pws_os::CUUID &entry_uuid)
	{
		return m_pwlist.find(entry_uuid);
	}
	ItemListConstIter Find(const pws_os::CUUID &entry_uuid) const
	{
		return m_pwlist.find(entry_uuid);
	}

	void ProcessReadEntry(CItemData &ci_temp,
		std::vector<st_GroupTitleUser> &vGTU_INVALID_UUID,
		std::vector<st_GroupTitleUser> &vGTU_DUPLICATE_UUID,
		st_ValidateResults &st_vr);
	// Validate() returns true if data modified, false if all OK
	bool Validate(const size_t iMAXCHARS, st_ValidateResults &st_vr);

	void ParseDependants(); // populate data structures as needed - called in ReadFile()

	// Keyboard shortcuts
	/*bool AddKBShortcut(const int32 &iKBShortcut, const pws_os::CUUID &uuid);
	bool DelKBShortcut(const int32 &iKBShortcut, const pws_os::CUUID &uuid);
	const pws_os::CUUID & GetKBShortcut(const int32 &iKBShortcut);
	const KBShortcutMap &GetAllKBShortcuts() { return m_KBShortcutMap; }*/
	void SetAppHotKey(const int32 &iAppHotKey) { m_iAppHotKey = iAppHotKey; }
	int32 GetAppHotKey() const { return m_iAppHotKey; }

	// Set application data
	void SetApplicationNameAndVersion(const stringT &appName, DWORD dwMajorMinor);

	// Use following calls to 'SetChanged' & 'SetDBChanged' sparingly
	// outside of core
	void SetChanged(const bool bDBChanged, const bool bDBprefschanged)
	{
		m_bDBChanged = bDBChanged;
		m_bDBPrefsChanged = bDBprefschanged;
		NotifyDBModified();
	}
	void SetDBChanged(bool bDBChanged, bool bNotify = true)
	{
		m_bDBChanged = bDBChanged;
		if (bNotify) NotifyDBModified();
	}

	// Callback to be notified if the database changes
	void NotifyDBModified();

	bool HasAtt(const pws_os::CUUID &attuuid) const { return m_attlist.find(attuuid) != m_attlist.end(); }

protected:

private:
	virtual int DoAddDependentEntries(UUIDVector &dependentslist,
		const CItemData::EntryType type,
		const int &iVia,
		ItemList *pmapDeletedItems = NULL,
		SaveTypePWMap *pmapSaveTypePW = NULL);

	StringX m_currfile; // current pw db filespec

	unsigned char *m_passkey; // encrypted by session key
	size_t m_passkey_len; // Length of cleartext passkey

	uint32 m_hashIters; // for new or currently open db.

	static unsigned char m_session_key[32];
	static unsigned char m_session_initialized;

	HANDLE m_lockFileHandle;
	HANDLE m_lockFileHandle2;
	int m_LockCount;
	int m_LockCount2;

	stringT m_AppNameAndVersion;
	PWSfile::VERSION m_ReadFileVersion;

	bool m_bDBChanged;
	bool m_bDBPrefsChanged;
	bool m_IsReadOnly;
	bool m_bUniqueGTUValidated;

	PWSfileHeader m_hdr;
	std::vector<bool> m_OrigDisplayStatus;

	// THE password database
	//  Key = entry's uuid; Value = entry's CItemData
	ItemList m_pwlist;

	// Attachments, if any
	AttList m_attlist;

	// Alias/Shortcut structures
	// Permanent Multimap: since potentially more than one alias/shortcut per base
	//  Key = base uuid; Value = multiple alias/shortcut uuids
	ItemMMap m_base2aliases_mmap;
	ItemMMap m_base2shortcuts_mmap;

	// Following are private in PWScore, public in CommandInterface:
	/*const ItemMMap &GetBase2AliasesMmap() const { return m_base2aliases_mmap; }
	void SetBase2AliasesMmap(ItemMMap &b2amm) { m_base2aliases_mmap = b2amm; }
	const ItemMMap &GetBase2ShortcutsMmap() const { return m_base2shortcuts_mmap; }
	void SetBase2ShortcutsMmap(ItemMMap &b2smm) { m_base2shortcuts_mmap = b2smm; }*/

	// Changed groups
	std::vector<StringX> m_vnodes_modified;

	static Reporter *m_pReporter; // set as soon as possible to show errors
	static Asker *m_pAsker;
	PWSFileSig *m_pFileSig;

	UnknownFieldList m_UHFL;
	int m_nRecordsWithUnknownFields;
	
	UUIDList m_RUEList;

	bool m_bNotifyDB;

	UIInterFace *m_pUIIF; // pointer to UI interface abtraction
	std::bitset<UIInterFace::NUM_SUPPORTED> m_bsSupportedFunctions;
		
	int32 m_iAppHotKey;
};

#endif /* __PWSCORE_H */
