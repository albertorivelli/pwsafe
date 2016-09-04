/*
* Copyright (c) 2003-2016 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/
// file PWScore.cpp
//-----------------------------------------------------------------------------

#include "PWScore.h"
#include "core.h"
#include "TwoFish.h"
//#include "PWSprefs.h"
#include "PWSrand.h"
#include "Util.h"
//#include "SysInfo.h"
#include "UTF8Conv.h"
//#include "Report.h"
//#include "VerifyFormat.h"
//#include "StringXStream.h"

//#include "os/pws_tchar.h"
#include "os/typedefs.h"
//#include "os/dir.h"
//#include "os/debug.h"
//#include "os/file.h"
//#include "os/mem.h"
//#include "os/logit.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include <set>
#include <iterator>

extern const TCHAR *GROUPTITLEUSERINCHEVRONS;

using pws_os::CUUID;

unsigned char PWScore::m_session_key[32];
unsigned char PWScore::m_session_initialized = false;
Asker *PWScore::m_pAsker = NULL;
Reporter *PWScore::m_pReporter = NULL;

// Following structure used in ReadFile and Validate and entries using
// Named Password Policy
static bool GTUCompareV1(const st_GroupTitleUser &gtu1, const st_GroupTitleUser &gtu2)
{
	if (gtu1.group != gtu2.group)
		return gtu1.group.compare(gtu2.group) < 0;
	else if (gtu1.title != gtu2.title)
		return gtu1.title.compare(gtu2.title) < 0;
	else
		return gtu1.user.compare(gtu2.user) < 0;
}

// Helper struct for results of a database verification
struct st_ValidateResults {
	int num_invalid_UUIDs;
	int num_duplicate_UUIDs;
	int num_empty_titles;
	int num_empty_passwords;
	int num_duplicate_GTU_fixed;
	int num_PWH_fixed;
	int num_excessivetxt_found;
	int num_alias_warnings;
	int num_shortcuts_warnings;
	int num_missing_att;
	int num_orphan_att;

	st_ValidateResults()
		: num_invalid_UUIDs(0), num_duplicate_UUIDs(0),
		num_empty_titles(0), num_empty_passwords(0),
		num_duplicate_GTU_fixed(0),
		num_PWH_fixed(0), num_excessivetxt_found(0),
		num_alias_warnings(0), num_shortcuts_warnings(0),
		num_missing_att(0), num_orphan_att(0)
	{}

	st_ValidateResults(const st_ValidateResults &that)
		: num_invalid_UUIDs(that.num_invalid_UUIDs),
		num_duplicate_UUIDs(that.num_duplicate_UUIDs),
		num_empty_titles(that.num_empty_titles),
		num_empty_passwords(that.num_empty_passwords),
		num_duplicate_GTU_fixed(that.num_duplicate_GTU_fixed),
		num_PWH_fixed(that.num_PWH_fixed),
		num_excessivetxt_found(that.num_excessivetxt_found),
		num_alias_warnings(that.num_alias_warnings),
		num_shortcuts_warnings(that.num_shortcuts_warnings),
		num_missing_att(that.num_missing_att), num_orphan_att(that.num_orphan_att)
	{}

	st_ValidateResults &operator=(const st_ValidateResults &that) {
		if (this != &that) {
			num_invalid_UUIDs = that.num_invalid_UUIDs;
			num_duplicate_UUIDs = that.num_duplicate_UUIDs;
			num_empty_titles = that.num_empty_titles;
			num_empty_passwords = that.num_empty_passwords;
			num_duplicate_GTU_fixed = that.num_duplicate_GTU_fixed;
			num_PWH_fixed = that.num_PWH_fixed;
			num_excessivetxt_found = that.num_excessivetxt_found;
			num_alias_warnings = that.num_alias_warnings;
			num_shortcuts_warnings = that.num_shortcuts_warnings;
			num_missing_att = that.num_missing_att;
			num_orphan_att = that.num_orphan_att;
		}
		return *this;
	}

	int TotalIssues()
	{
		return (num_invalid_UUIDs + num_duplicate_UUIDs +
			num_empty_titles + num_empty_passwords +
			num_duplicate_GTU_fixed +
			num_PWH_fixed + num_excessivetxt_found +
			num_alias_warnings + num_shortcuts_warnings +
			num_missing_att + num_orphan_att);
	}
};

//-----------------------------------------------------------------

PWScore::PWScore() :
	//m_isAuxCore(false),
	m_currfile(_T("")),
	m_passkey(NULL), m_passkey_len(0),
	m_hashIters(MIN_HASH_ITERATIONS),
	m_lockFileHandle(INVALID_HANDLE_VALUE),
	m_lockFileHandle2(INVALID_HANDLE_VALUE),
	m_LockCount(0), m_LockCount2(0),
	m_ReadFileVersion(PWSfile::UNKNOWN_VERSION),
	m_bDBChanged(false), m_bDBPrefsChanged(false),
	m_IsReadOnly(false), m_bUniqueGTUValidated(false),
	//m_nRecordsWithUnknownFields(0),
	m_bNotifyDB(false), m_pUIIF(NULL), m_pFileSig(NULL),
	m_iAppHotKey(0)
{
	// following should ideally be wrapped in a mutex
	/*if (!PWScore::m_session_initialized) {
		PWScore::m_session_initialized = true;
		pws_os::mlock(m_session_key, sizeof(m_session_key));
		PWSrand::GetInstance()->GetRandomData(m_session_key, sizeof(m_session_key));
		if (!pws_os::mcryptProtect(m_session_key, sizeof(m_session_key))) {
			pws_os::Trace(_T("pws_os::mcryptProtect failed"));
		}
	}
	m_undo_iter = m_redo_iter = m_vpcommands.end();*/
}

PWScore::~PWScore()
{
	// do NOT trash m_session_*, as there may be other cores around
	// relying on it. Trashing the ciphertext encrypted with it is enough
	const unsigned int BS = TwoFish::BLOCKSIZE;
	if (m_passkey_len > 0) {
		trashMemory(m_passkey, ((m_passkey_len + (BS - 1)) / BS) * BS);
		delete[] m_passkey;
		m_passkey = NULL;
		m_passkey_len = 0;
	}

	m_UHFL.clear();
	m_vnodes_modified.clear();

	delete m_pFileSig;
}

void PWScore::SetApplicationNameAndVersion(const stringT &appName,
	DWORD dwMajorMinor)
{
	int nMajor = HIWORD(dwMajorMinor);
	int nMinor = LOWORD(dwMajorMinor);
	Format(m_AppNameAndVersion, L"%ls V%d.%02d", appName.c_str(),
		nMajor, nMinor);
}

// For Validate only
struct st_GroupTitleUser2 {
	StringX group;
	StringX title;
	StringX user;
	StringX newtitle;

	st_GroupTitleUser2() {}

	st_GroupTitleUser2(const StringX &g, const StringX &t, const StringX &u,
		const StringX &n)
		: group(g), title(t), user(u), newtitle(n) {}

	st_GroupTitleUser2 &operator=(const st_GroupTitleUser2 &that) {
		if (this != &that) {
			group = that.group; title = that.title; user = that.user;
			newtitle = that.newtitle;
		}
		return *this;
	}
};

// For Validate only
struct st_AttTitle_Filename {
	StringX title;
	StringX filename;

	st_AttTitle_Filename() {}

	st_AttTitle_Filename(const StringX &t, const StringX &fn)
		: title(t), filename(fn) {}

	st_AttTitle_Filename &operator=(const st_AttTitle_Filename &that) {
		if (this != &that) {
			title = that.title; filename = that.filename;
		}
		return *this;
	}
};

void PWScore::ParseDependants()
{
	UUIDVector Possible_Aliases, Possible_Shortcuts;

	for (ItemListIter iter = m_pwlist.begin(); iter != m_pwlist.end(); iter++) {
		const CItemData &ci = iter->second;
		// Get all possible Aliases/Shortcuts for future checking if base entries exist
		if (ci.IsAlias()) {
			Possible_Aliases.push_back(ci.GetUUID());
		}
		else if (ci.IsShortcut()) {
			Possible_Shortcuts.push_back(ci.GetUUID());
		}
		// Set refcount on attachments
		if (ci.HasAttRef()) {
			auto attIter = m_attlist.find(ci.GetAttUUID());
			if (attIter != m_attlist.end())
				attIter->second.IncRefcount();
			//else
			//	pws_os::Trace(_T("dangling ATTREF")); // will be caught in validate
		}
	} // iter over m_pwlist

	if (!Possible_Aliases.empty()) {
		DoAddDependentEntries(Possible_Aliases, CItemData::ET_ALIAS, CItemData::UUID);
	}

	if (!Possible_Shortcuts.empty()) {
		DoAddDependentEntries(Possible_Shortcuts, CItemData::ET_SHORTCUT, CItemData::UUID);
	}
}

bool PWScore::Validate(const size_t iMAXCHARS, st_ValidateResults &st_vr)
{
	/*
	1. Check PWH is valid
	2. Check that the 2 mandatory fields are present (Title & Password)
	3. Check group/title/user must be unique.
	4. Check that no text field has more than iMAXCHARS, that can displayed
	in the GUI's text control.
	5. For attachments (V4):
	5.1 Check that each ATTREF in a data entry has a corresponding ItemAtt
	5.2 Check that each ItemAtt has a corresponding "owner" ItemData

	Note:
	m_pwlist is implemented as a map keyed on UUIDs, each entry is
	guaranteed to have a unique uuid. The uniqueness invariant
	should be enforced elsewhere.
	(ReadFile during Open and Import have already ensured UUIDs are unique
	and valid)
	*/

	int n = -1;
	size_t uimaxsize(0);

	stringT cs_Error;
	//pws_os::Trace(_T("Start validation\n"));

	st_GroupTitleUser st_gtu;
	GTUSet setGTU;
	GTUSetPair pr_gtu;
	std::vector<st_GroupTitleUser> vGTU_UUID, vGTU_EmptyPassword, vGTU_PWH, vGTU_TEXT,
		                           vGTU_ALIASES, vGTU_SHORTCUTS;
	std::vector<st_GroupTitleUser2> vGTU_NONUNIQUE, vGTU_EmptyTitle;
	std::vector<st_GroupTitleUser> vGTU_MissingAtt;
	std::vector<st_AttTitle_Filename> vOrphanAtt;
	std::set<CUUID> sAtts;

	ItemListIter iter;

	for (iter = m_pwlist.begin(); iter != m_pwlist.end(); iter++) {
		CItemData &ci = iter->second;
		CItemData fixedItem(ci);
		bool bFixed(false);

		n++;

		// Fix GTU uniqueness - can't do this in a CItemData member function as it causes
		// circular includes:
		//  "ItemData.h" would need to include "coredefs.h", which needs to include "ItemData.h"!
		StringX sxgroup(ci.GetGroup()), sxtitle(ci.GetTitle()), sxuser(ci.GetUser());
		st_gtu.group = sxgroup;
		st_gtu.title = sxtitle;
		st_gtu.user = sxuser;

		if (sxtitle.empty()) {
			// This field is mandatory!
			// Change it and insert into a std::set which guarantees uniqueness
			int i = 0;
			StringX sxnewtitle(sxtitle);
			do {
				i++;
				Format(sxnewtitle, 3436, i);
				st_gtu.title = sxnewtitle;
				pr_gtu = setGTU.insert(st_gtu);
			} while (!pr_gtu.second);

			fixedItem.SetTitle(sxnewtitle);

			bFixed = true;
			vGTU_EmptyTitle.push_back(st_GroupTitleUser2(sxgroup, sxtitle, sxuser, sxnewtitle));
			st_vr.num_empty_titles++;
			sxtitle = sxnewtitle;
		}
		else {
			// Title was not empty
			// Insert into a std::set which guarantees uniqueness
			pr_gtu = setGTU.insert(st_gtu);
			if (!pr_gtu.second) {
				// Already have this group/title/user entry
				int i = 0;
				StringX s_copy, sxnewtitle(sxtitle);
				do {
					i++;
					Format(s_copy, IDSC_DUPLICATENUMBER, i);
					sxnewtitle = sxtitle + s_copy;
					st_gtu.title = sxnewtitle;
					pr_gtu = setGTU.insert(st_gtu);
				} while (!pr_gtu.second);

				fixedItem.SetTitle(sxnewtitle);

				bFixed = true;
				vGTU_NONUNIQUE.push_back(st_GroupTitleUser2(sxgroup, sxtitle, sxuser, sxnewtitle));
				st_vr.num_duplicate_GTU_fixed++;
				sxtitle = sxnewtitle;
			}
		}

		// Test if Password is present as it is mandatory! was fixed
		if (ci.GetPassword().empty()) {
			StringX sxMissingPassword;
			LoadAString(sxMissingPassword, IDSC_MISSINGPASSWORD);
			fixedItem.SetPassword(sxMissingPassword);

			bFixed = true;
			vGTU_EmptyPassword.push_back(st_GroupTitleUser(sxgroup, sxtitle, sxuser));
			st_vr.num_empty_passwords++;
		}

		// Test if Password History was fixed
		if (!fixedItem.ValidatePWHistory()) {
			bFixed = true;
			vGTU_PWH.push_back(st_GroupTitleUser(sxgroup, sxtitle, sxuser));
			st_vr.num_PWH_fixed++;
		}

		// Note excessively sized text fields
		if (iMAXCHARS > 0) {
			bool bEntryHasBigField(false);
			for (unsigned char uc = static_cast<unsigned char>(CItem::GROUP);
				uc < static_cast<unsigned char>(CItem::LAST_DATA); uc++) {
				if (CItemData::IsTextField(uc)) {
					StringX sxvalue = ci.GetFieldValue(static_cast<CItemData::FieldType>(uc));
					if (sxvalue.length() > iMAXCHARS) {
						bEntryHasBigField = true;
						//  We don't truncate the field, but if we did, then the the code would be:
						//  fixedItem.SetFieldValue((CItemData::FieldType)uc, sxvalue.substr(0, iMAXCHARS))
						break;
					}
				}
			}
			if (bEntryHasBigField) {
				uimaxsize = (std::max)(uimaxsize, ci.GetSize());
				vGTU_TEXT.push_back(st_GroupTitleUser(sxgroup, sxtitle, sxuser));
				st_vr.num_excessivetxt_found++;
			}
		}

		// Attachment Reference check (5.1)
		if (ci.HasAttRef()) {
			sAtts.insert(ci.GetAttUUID());
			if (!HasAtt(ci.GetAttUUID())) {
				vGTU_MissingAtt.push_back(st_GroupTitleUser(ci.GetGroup(),
					                                        ci.GetTitle(),
					                                        ci.GetUser()));
				st_vr.num_missing_att++;
				// Fix the problem:
				fixedItem.ClearAttUUID();
				bFixed = true;
			}
		}

		if (bFixed) {
			// Mark as modified
			fixedItem.SetStatus(CItemData::ES_MODIFIED);
			// We assume that this is run during file read. If not, then we
			// need to run using the Command mechanism for Undo/Redo.
			m_pwlist[fixedItem.GetUUID()] = fixedItem;
		}
	} // iteration over m_pwlist

	// Check for orphan attachments (5.2)
	for (auto att_iter = m_attlist.begin(); att_iter != m_attlist.end(); att_iter++) {
		if (sAtts.find(att_iter->first) == sAtts.end()) {
			st_AttTitle_Filename stATFN;
			stATFN.title = att_iter->second.GetTitle();
			stATFN.filename = att_iter->second.GetFileName();
			vOrphanAtt.push_back(stATFN);
			st_vr.num_orphan_att++;
			// NOT removing attachment for now. Add support for exporting orphans later.
		}
	}

	//pws_os::Trace(_T("End validation. %d entries processed\n"), n + 1);
	
	m_bUniqueGTUValidated = true;
	if (st_vr.TotalIssues() > 0) {
		SetDBChanged(true);
		return true;
	}
	else {
		return false;
	}
	// CppCheck says: "error: Memory leak: pmulticmds".  I can't see these commands executed either!
}

int PWScore::DoAddDependentEntries(UUIDVector &dependentlist,
	const CItemData::EntryType type, const int &iVia,
	ItemList *pmapDeletedItems,
	SaveTypePWMap *pmapSaveTypePW)
{
	// When called during validation of a database  - *pRpt is valid
	// When called during the opening of a database or during drag & drop
	//   - *pRpt is NULL and no report generated

	// type is either CItemData::ET_ALIAS or CItemData::ET_SHORTCUT

	// If iVia == CItemData::UUID, the password was "[[uuidstr]]" or "[~uuidstr~]" of the
	//   associated base entry
	// If iVia == CItemData::PASSWORD, the password is expected to be in the full format
	// [g:t:u], where g and/or u may be empty.

	if (pmapDeletedItems != NULL)
		pmapDeletedItems->clear();

	if (pmapSaveTypePW != NULL)
		pmapSaveTypePW->clear();

	ItemMMap *pmmap;
	if (type == CItemData::ET_ALIAS) {
		pmmap = &m_base2aliases_mmap;
	}
	else if (type == CItemData::ET_SHORTCUT) {
		pmmap = &m_base2shortcuts_mmap;
	}
	else
		return -1;

	int num_warnings(0);
	st_SaveTypePW st_typepw;

	if (!dependentlist.empty()) {
		UUIDVectorIter paiter;
		ItemListIter iter;
		StringX sxPwdGroup, sxPwdTitle, sxPwdUser, tmp;
		CUUID base_uuid(CUUID::NullUUID());
		bool bwarnings(false);
		stringT strError;

		for (paiter = dependentlist.begin();
			paiter != dependentlist.end(); paiter++) {
			iter = m_pwlist.find(*paiter);
			if (iter == m_pwlist.end())
				return num_warnings;

			CItemData *pci_curitem = &iter->second;
			CUUID entry_uuid = pci_curitem->GetUUID();

			if (iVia == CItemData::UUID) {
				base_uuid = pci_curitem->GetBaseUUID();
				iter = m_pwlist.find(base_uuid);
			}
			else {
				tmp = pci_curitem->GetPassword();
				// Remove leading '[['/'[~' & trailing ']]'/'~]'
				tmp = tmp.substr(2, tmp.length() - 4);
				if (std::count(tmp.begin(), tmp.end(), _T(':')) == 2) {
					sxPwdGroup = tmp.substr(0, tmp.find_first_of(_T(":")));
					// Skip over 'group:'
					tmp = tmp.substr(sxPwdGroup.length() + 1);
					sxPwdTitle = tmp.substr(0, tmp.find_first_of(_T(":")));
					// Skip over 'title:'
					sxPwdUser = tmp.substr(sxPwdTitle.length() + 1);
					iter = Find(sxPwdGroup, sxPwdTitle, sxPwdUser);
					base_uuid = iter->second.GetUUID();
				}
				else {
					iter = m_pwlist.end();
				}
			}

			if (iter != m_pwlist.end()) {
				//ASSERT(base_uuid != CUUID::NullUUID());
				pci_curitem->SetBaseUUID(base_uuid);
				if (type == CItemData::ET_SHORTCUT) {
					// Adding shortcuts -> Base must be normal or already a shortcut base
					if (!iter->second.IsNormal() && !iter->second.IsShortcutBase()) {
						//// Bad news!
						//if (pRpt != NULL) {
						//	if (!bwarnings) {
						//		bwarnings = true;
						//		LoadAString(strError, IDSC_IMPORTWARNINGHDR);
						//		pRpt->WriteLine(strError);
						//	}
						//	stringT cs_type;
						//	LoadAString(cs_type, IDSC_SHORTCUT);
						//	Format(strError, IDSC_IMPORTWARNING3, cs_type.c_str(),
						//		pci_curitem->GetGroup().c_str(), pci_curitem->GetTitle().c_str(),
						//		pci_curitem->GetUser().c_str(), cs_type.c_str());
						//	pRpt->WriteLine(strError);
						//}
						// Invalid - delete!
						if (pmapDeletedItems != NULL)
							pmapDeletedItems->insert(ItemList_Pair(*paiter, *pci_curitem));
						m_pwlist.erase(iter);
						continue;
					}
				}
				if (type == CItemData::ET_ALIAS) {
					// Adding Aliases -> Base must be normal or already a alias base
					if (!iter->second.IsNormal() && !iter->second.IsAliasBase()) {
						//// Bad news!
						//if (pRpt != NULL) {
						//	if (!bwarnings) {
						//		bwarnings = true;
						//		LoadAString(strError, IDSC_IMPORTWARNINGHDR);
						//		pRpt->WriteLine(strError);
						//	}
						//	stringT cs_type;
						//	LoadAString(cs_type, IDSC_ALIAS);
						//	Format(strError, IDSC_IMPORTWARNING3, cs_type.c_str(),
						//		pci_curitem->GetGroup().c_str(), pci_curitem->GetTitle().c_str(),
						//		pci_curitem->GetUser().c_str(), cs_type.c_str());
						//	pRpt->WriteLine(strError);
						//}
						// Invalid - delete!
						if (pmapDeletedItems != NULL)
							pmapDeletedItems->insert(ItemList_Pair(*paiter, *pci_curitem));
						m_pwlist.erase(iter);
						continue;
					}
					if (iter->second.IsAlias()) {
						// This is an alias too!  Not allowed!  Make new one point to original base
						// Note: this may be random as who knows the order of reading records?
						CUUID temp_uuid = iter->second.GetUUID();
						base_uuid = iter->second.GetBaseUUID(); // ??? used here ???
						/*if (pRpt != NULL) {
							if (!bwarnings) {
								bwarnings = true;
								LoadAString(strError, IDSC_IMPORTWARNINGHDR);
								pRpt->WriteLine(strError);
							}
							Format(strError, IDSC_IMPORTWARNING1, pci_curitem->GetGroup().c_str(),
								pci_curitem->GetTitle().c_str(), pci_curitem->GetUser().c_str());
							pRpt->WriteLine(strError);
							LoadAString(strError, IDSC_IMPORTWARNING1A);
							pRpt->WriteLine(strError);
						}*/
						if (pmapSaveTypePW != NULL) {
							st_typepw.et = iter->second.GetEntryType();
							st_typepw.sxpw = _T("");
							pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
						}
						pci_curitem->SetAlias();
						num_warnings++;
					}
				}
				base_uuid = iter->second.GetUUID();
				if (type == CItemData::ET_ALIAS) {
					if (pmapSaveTypePW != NULL) {
						st_typepw.et = iter->second.GetEntryType();
						st_typepw.sxpw = _T("");
						pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
					}
					iter->second.SetAliasBase();
				}
				else
					if (type == CItemData::ET_SHORTCUT) {
						if (pmapSaveTypePW != NULL) {
							st_typepw.et = iter->second.GetEntryType();
							st_typepw.sxpw = _T("");
							pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
						}
						iter->second.SetShortcutBase();
					}

				pmmap->insert(ItemMMap_Pair(base_uuid, entry_uuid));
				if (type == CItemData::ET_ALIAS) {
					if (pmapSaveTypePW != NULL) {
						st_typepw.et = iter->second.GetEntryType();
						st_typepw.sxpw = pci_curitem->GetPassword();
						pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
					}
					pci_curitem->SetPassword(_T("[Alias]"));
					pci_curitem->SetAlias();
				}
				else
				{
					if (type == CItemData::ET_SHORTCUT) {
						if (pmapSaveTypePW != NULL) {
							st_typepw.et = iter->second.GetEntryType();
							st_typepw.sxpw = pci_curitem->GetPassword();
							pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
						}
						pci_curitem->SetPassword(_T("[Shortcut]"));
						pci_curitem->SetShortcut();
					}
				}
					
			}
			else {
				//// Specified base does not exist!
				//if (pRpt != NULL) {
				//	if (!bwarnings) {
				//		bwarnings = true;
				//		LoadAString(strError, IDSC_IMPORTWARNINGHDR);
				//		pRpt->WriteLine(strError);
				//	}
				//	Format(strError, IDSC_IMPORTWARNING2, pci_curitem->GetGroup().c_str(),
				//		pci_curitem->GetTitle().c_str(), pci_curitem->GetUser().c_str());
				//	pRpt->WriteLine(strError);
				//	LoadAString(strError, IDSC_IMPORTWARNING2A);
				//	pRpt->WriteLine(strError);
				//}
				if (type == CItemData::ET_SHORTCUT) {
					if (pmapDeletedItems != NULL)
						pmapDeletedItems->insert(ItemList_Pair(*paiter, *pci_curitem));
				}
				else {
					if (pmapSaveTypePW != NULL) {
						st_typepw.et = CItemData::ET_ALIAS;
						st_typepw.sxpw = _T("");
						pmapSaveTypePW->insert(SaveTypePWMap_Pair(*paiter, st_typepw));
					}
					pci_curitem->SetNormal(); // but can make invalid alias a normal entry
				}

				num_warnings++;
			}
		}
	}
	return num_warnings;
}

bool PWScore::SetUIInterFace(UIInterFace *pUIIF, size_t numsupported, std::bitset<UIInterFace::NUM_SUPPORTED> bsSupportedFunctions)
{
	bool brc(true);
	m_pUIIF = pUIIF;
	//ASSERT(numsupported == UIInterFace::NUM_SUPPORTED);

	m_bsSupportedFunctions.reset();
	if (numsupported == UIInterFace::NUM_SUPPORTED) {
		m_bsSupportedFunctions = bsSupportedFunctions;
	}
	else {
		size_t minsupported = (std::min)(numsupported, size_t(UIInterFace::NUM_SUPPORTED));
		for (size_t i = 0; i < minsupported; i++) {
			m_bsSupportedFunctions.set(i, bsSupportedFunctions.test(i));
		}
		brc = false;
	}
	return brc;
}

void PWScore::ClearData(void)
{
	const unsigned int BS = TwoFish::BLOCKSIZE;
	if (m_passkey_len > 0) {
		trashMemory(m_passkey, ((m_passkey_len + (BS - 1)) / BS) * BS);
		delete[] m_passkey;
		m_passkey = NULL;
		m_passkey_len = 0;
	}
	m_passkey = NULL;

	//Composed of ciphertext, so doesn't need to be overwritten
	m_pwlist.clear();
	m_attlist.clear();

	// Clear out out dependents mappings
	m_base2aliases_mmap.clear();
	m_base2shortcuts_mmap.clear();

	// Clear out unknown fields
	m_UHFL.clear();

	// Clear out database filters
	//m_MapFilters.clear();

	// Clear out policies
	//m_MapPSWDPLC.clear();

	// Clear out Empty Groups
	//m_vEmptyGroups.clear();

	// Clear out commands
	//ClearCommands();
}

void PWScore::EncryptPassword(const unsigned char *plaintext, size_t len,
	unsigned char *ciphertext) const
{
	// Chicken out of an interface change, or just a sanity check?
	// Maybe both...
	//ASSERT(len > 0);
	unsigned int ulen = static_cast<unsigned int>(len);

	const unsigned int BS = TwoFish::BLOCKSIZE;

	//if (!pws_os::mcryptUnprotect(m_session_key, sizeof(m_session_key))) {
	//	//pws_os::Trace(_T("pws_os::mcryptUnprotect failed"));
	//}
	TwoFish tf(m_session_key, sizeof(m_session_key));
	//if (!pws_os::mcryptProtect(m_session_key, sizeof(m_session_key))) {
	//	//pws_os::Trace(_T("pws_os::mcryptProtect failed"));
	//}
	unsigned int BlockLength = ((ulen + (BS - 1)) / BS) * BS;
	unsigned char curblock[BS];

	for (unsigned int x = 0; x < BlockLength; x += BS) {
		unsigned int i;
		if ((ulen == 0) ||
			((ulen % BS != 0) && (ulen - x < BS))) {
			//This is for an uneven last block
			memset(curblock, 0, BS);
			for (i = 0; i < len % BS; i++)
				curblock[i] = plaintext[x + i];
		}
		else
			for (i = 0; i < BS; i++) {
				curblock[i] = plaintext[x + i];
			}
		tf.Encrypt(curblock, curblock);
		memcpy(ciphertext + x, curblock, BS);
	}
	trashMemory(curblock, sizeof(curblock));
}

void PWScore::SetPassKey(const StringX &new_passkey)
{
	// Only used when opening files and for new files
	const unsigned int BS = TwoFish::BLOCKSIZE;
	// if changing, clear old
	if (m_passkey_len > 0) {
		trashMemory(m_passkey, ((m_passkey_len + (BS - 1)) / BS) * BS);
		delete[] m_passkey;
	}

	m_passkey_len = new_passkey.length() * sizeof(TCHAR);

	size_t BlockLength = ((m_passkey_len + (BS - 1)) / BS) * BS;
	m_passkey = new unsigned char[BlockLength];
	LPCTSTR plaintext = LPCTSTR(new_passkey.c_str());
	EncryptPassword(reinterpret_cast<const unsigned char *>(plaintext), m_passkey_len, m_passkey);
}

StringX PWScore::GetPassKey() const
{
	StringX retval(_T(""));
	if (m_passkey_len > 0) {
		const unsigned int BS = TwoFish::BLOCKSIZE;
		size_t BlockLength = ((m_passkey_len + (BS - 1)) / BS) * BS;
		//if (!pws_os::mcryptUnprotect(m_session_key, sizeof(m_session_key))) {
		//	//pws_os::Trace(_T("pws_os::mcryptUnprotect failed"));
		//}
		TwoFish tf(m_session_key, sizeof(m_session_key));
		//if (!pws_os::mcryptProtect(m_session_key, sizeof(m_session_key))) {
		//	//pws_os::Trace(_T("pws_os::mcryptProtect failed"));
		//}
		unsigned char curblock[BS];
		for (unsigned int x = 0; x < BlockLength; x += BS) {
			unsigned int i;
			for (i = 0; i < BS; i++) {
				curblock[i] = m_passkey[x + i];
			}

			tf.Decrypt(curblock, curblock);
			for (i = 0; i < BS; i += sizeof(TCHAR)) {
				if (x + i < m_passkey_len) {
					retval += *(reinterpret_cast<TCHAR*>(curblock + i));
				}
			}
		}
		trashMemory(curblock, sizeof(curblock));
	}
	return retval;
}

static void TestAndFixNullUUID(CItemData &ci_temp,
	std::vector<st_GroupTitleUser> &vGTU_INVALID_UUID,
	st_ValidateResults &st_vr)
{
	/*
	* If, for some reason, we're reading in an invalid UUID,
	* we will change the UUID before adding it to the list.
	*
	* To date, we know that databases of format 0x0200 and 0x0300 have a UUID
	* problem if records were duplicated.  Databases of format 0x0100 did not
	* have the duplicate function and it has been fixed in databases in format
	* 0x0301 and so not an issue in V1 (0x0100) or V3.03 (0x0301) or later
	*
	* But a Null CUUID is invalid even if another application using core.lib
	* does it and they could have got the version wrong - so fix it anyway
	*/
	if (ci_temp.GetUUID() == CUUID::NullUUID()) {
		vGTU_INVALID_UUID.push_back(st_GroupTitleUser(ci_temp.GetGroup(),
			ci_temp.GetTitle(), ci_temp.GetUser()));
		st_vr.num_invalid_UUIDs++;
		ci_temp.CreateUUID(); // replace invalid UUID
		ci_temp.SetStatus(CItemData::ES_MODIFIED);  // Show modified
	} // UUID invalid
}

static void TestAndFixDupUUID(CItemData &ci_temp, const PWScore &core,
	std::vector<st_GroupTitleUser> &vGTU_DUPLICATE_UUID,
	st_ValidateResults &st_vr)
{
	/*
	* If, for some reason, we're reading in a UUID that we already have
	* we will change the UUID, rather than overwrite an entry.
	* This is to protect the user from possible bugs that break
	* the uniqueness requirement of UUIDs.
	*/
	if (core.Find(ci_temp.GetUUID()) != core.GetEntryEndIter()) {
		vGTU_DUPLICATE_UUID.push_back(st_GroupTitleUser(ci_temp.GetGroup(),
			ci_temp.GetTitle(), ci_temp.GetUser()));
		st_vr.num_duplicate_UUIDs++;
		ci_temp.CreateUUID(); // replace duplicated UUID
		ci_temp.SetStatus(CItemData::ES_MODIFIED);  // Show modified
	} // UUID duplicate
}

//static void ProcessPasswordPolicy(CItemData &ci_temp, PWScore &core)
//{
//	if (ci_temp.IsPasswordPolicySet() && ci_temp.IsPolicyNameSet()) {
//		// Error: can't have both - clear Password Policy Name
//		ci_temp.ClearField(CItemData::POLICYNAME);
//	}
//
//	if (ci_temp.IsPolicyNameSet()) {
//		if (!core.IncrementPasswordPolicy(ci_temp.GetPolicyName())) {
//			// Map name not present in database - clear it!
//			ci_temp.ClearField(CItemData::POLICYNAME);
//		}
//	}
//}

void PWScore::ProcessReadEntry(CItemData &ci_temp,
	std::vector<st_GroupTitleUser> &vGTU_INVALID_UUID,
	std::vector<st_GroupTitleUser> &vGTU_DUPLICATE_UUID,
	st_ValidateResults &st_vr)
{
	TestAndFixNullUUID(ci_temp, vGTU_INVALID_UUID, st_vr);
	TestAndFixDupUUID(ci_temp, *this, vGTU_DUPLICATE_UUID, st_vr);
	//ProcessPasswordPolicy(ci_temp, *this);

	//int32 iKBShortcut;
	//ci_temp.GetKBShortcut(iKBShortcut);
	//if (iKBShortcut != 0) {
	//	// Entry can't have same shortcut as the Application's HotKey
	//	if (m_iAppHotKey == iKBShortcut) {
	//		ci_temp.SetKBShortcut(0);
	//	}
	//	else { // non-zero shortcut != app hotkey
	//		if (!ValidateKBShortcut(iKBShortcut)) {
	//			m_KBShortcutMap.insert(KBShortcutMapPair(iKBShortcut, ci_temp.GetUUID()));
	//		}
	//		else {
	//			ci_temp.SetKBShortcut(0);
	//		}
	//	}
	//} // non-zero shortcut

	//  // Possibly expired?
	//time_t tttXTime;
	//ci_temp.GetXTime(tttXTime);
	//if (tttXTime != time_t(0)) {
	//	m_ExpireCandidates.push_back(ExpPWEntry(ci_temp));
	//}

	// Finally, add it to the list!
	m_pwlist.insert(std::make_pair(ci_temp.GetUUID(), ci_temp));
}

task<int> PWScore::CheckPasskey(const StringX &filename, const StringX &passkey)
{
	int status;

	if (!filename.empty())
		status = co_await PWSfile::CheckPasskey(filename, passkey, m_ReadFileVersion);
	else { // can happen if tries to export b4 save
		size_t t_passkey_len = passkey.length();
		if (t_passkey_len != m_passkey_len) // trivial test
			return WRONG_PASSWORD;
		size_t BlockLength = ((m_passkey_len + 7) / 8) * 8;
		unsigned char *t_passkey = new unsigned char[BlockLength];
		LPCTSTR plaintext = LPCTSTR(passkey.c_str());
		EncryptPassword(reinterpret_cast<const unsigned char *>(plaintext), t_passkey_len, t_passkey);
		if (memcmp(t_passkey, m_passkey, BlockLength) == 0)
			status = PWSfile::SUCCESS;
		else
			status = PWSfile::WRONG_PASSWORD;
		delete[] t_passkey;
	}

	return status;
}


task<int> PWScore::ReadFile(const StringX &a_filename, const StringX &a_passkey,
	const bool bValidate, const size_t iMAXCHARS)
{
	int status;
	st_ValidateResults st_vr;
	std::vector<st_GroupTitleUser> vGTU_INVALID_UUID, vGTU_DUPLICATE_UUID;

	// Clear any old expired password entries
	m_ExpireCandidates.clear();

	//// Clear any old entry keyboard shortcuts
	////m_KBShortcutMap.clear();

	PWSfile *in = co_await PWSfile::MakePWSfile(a_filename, a_passkey, m_ReadFileVersion,
		PWSfile::Read, status, m_pAsker, m_pReporter);

	if (status != PWSfile::SUCCESS) {
		delete in;
		return status;
	}

	status = co_await in->Open(a_passkey);

	// in the old times we could open even 1.x files
	// for compatibility reasons, we open them again, to see if this is really a "1.x" file
	if ((m_ReadFileVersion == PWSfile::V20) && (status == PWSfile::WRONG_VERSION)) {
		PWSfile::VERSION tmp_version;  // only for getting compatible to "1.x" files
		tmp_version = m_ReadFileVersion;
		m_ReadFileVersion = PWSfile::V17;

		//Closing previously opened file
		in->Close();
		in->SetCurVersion(PWSfile::V17);
		status = co_await in->Open(a_passkey);
		if (status != PWSfile::SUCCESS) {
			m_ReadFileVersion = tmp_version;
		}
	}

	if (status != PWSfile::SUCCESS) {
		delete in;
		return status;
	}

	if (m_ReadFileVersion == PWSfile::UNKNOWN_VERSION) {
		delete in;
		return UNKNOWN_VERSION;
	}

	m_hdr = in->GetHeader();
	m_OrigDisplayStatus = m_hdr.m_displaystatus; // for WasDisplayStatusChanged
	m_RUEList = m_hdr.m_RUEList;

	//if (!m_isAuxCore) { // aux. core does not modify db prefs in pref singleton
	//					// Get pref string and tree display status & who saved when
	//					// all possibly empty!
	//	PWSprefs *prefs = PWSprefs::GetInstance();
	//	prefs->Load(m_hdr.m_prefString);

	//	// prepare handling of pre-2.0 DEFUSERCHR conversion
	//	if (m_ReadFileVersion == PWSfile::V17) {
	//		in->SetDefUsername(prefs->GetPref(PWSprefs::DefaultUsername).c_str());
	//		m_hdr.m_nCurrentMajorVersion = PWSfile::V17;
	//		m_hdr.m_nCurrentMinorVersion = 0;
	//	}
	//	else {
	//		// for 2.0 & later...
	//		in->SetDefUsername(prefs->GetPref(PWSprefs::DefaultUsername).c_str());
	//	}
	//} // !m_isAuxCore

	ClearData(); //Before overwriting old data, but after opening the file...
	SetChanged(false, false);

	SetPassKey(a_passkey); // so user won't be prompted for saves

	CItemData ci_temp;
	bool go = true;

	m_hashIters = in->GetNHashIters();
	///*if (in->GetFilters() != NULL) m_MapFilters = *in->GetFilters();
	//if (in->GetPasswordPolicies() != NULL) m_MapPSWDPLC = *in->GetPasswordPolicies();
	//if (in->GetEmptyGroups() != NULL) m_vEmptyGroups = *in->GetEmptyGroups();*/

	/*if (pRpt != NULL) {
		std::wstring cs_title;
		LoadAString(cs_title, IDSC_RPTVALIDATE);
		pRpt->StartReport(cs_title.c_str(), m_currfile.c_str());
	}*/

	do {
		ci_temp.Clear(); // Rather than creating a new one each time.
		status = co_await in->ReadRecord(ci_temp);
		switch (status) {
		case PWSfile::FAILURE:
		{
			// Show a useful(?) error message - better than
			// silently losing data (but not by much)
			// Best if title intact. What to do if not?
			if (m_pReporter != NULL) {
				stringT cs_msg, cs_caption;
				LoadAString(cs_caption, 3245);
				Format(cs_msg, 3246, ci_temp.GetTitle().c_str());
				cs_msg = cs_caption + _S(": ") + cs_caption;
				(*m_pReporter)(cs_msg);
			}
		}
		// deliberate fall-through
		case PWSfile::SUCCESS:
			ProcessReadEntry(ci_temp, vGTU_INVALID_UUID, vGTU_DUPLICATE_UUID, st_vr);
			break;
		case PWSfile::WRONG_RECORD: {
			// See if this is a V4 attachment:
			CItemAtt att;
			status = att.Read(in);
			if (status == PWSfile::SUCCESS) {
				m_attlist.insert(std::make_pair(att.GetUUID(), att));
			}
			else {
				// XXX report problem!
			}
		}
									break;
		case PWSfile::END_OF_FILE:
			go = false;
			break;
		default:
			break;
		} // switch
	} while (go);

	ParseDependants();

	m_nRecordsWithUnknownFields = in->GetNumRecordsWithUnknownFields();
	in->GetUnknownHeaderFields(m_UHFL);
	int closeStatus = in->Close(); // in V3 & later this checks integrity
	delete in;

	//ReportReadErrors(pRpt, vGTU_INVALID_UUID, vGTU_DUPLICATE_UUID);
	
	// Validate rest of things in the database (excluding duplicate UUIDs fixed above
	// as needed for m_pwlist - map uses UUID as its key)
	bool bValidateRC = !vGTU_INVALID_UUID.empty() || !vGTU_DUPLICATE_UUID.empty();

	// Only do the rest if user hasn't explicitly disabled the checks
	// NOTE: When a "other" core is involved (Compare, Merge etc.), we NEVER validate
	// the "other" core.
	if (bValidate)
		bValidateRC = Validate(iMAXCHARS, st_vr);

	SetDBChanged(bValidateRC);

	// Setup file signature for checking file integrity upon backup.
	// Goal is to prevent overwriting a good backup with a corrupt file.
	/*if (a_filename == m_currfile) {
		delete m_pFileSig;
		m_pFileSig = new PWSFileSig(a_filename.c_str());
	}*/

	// Make return code negative if validation errors
	if (closeStatus == SUCCESS && bValidateRC)
		closeStatus = OK_WITH_VALIDATION_ERRORS;

	return closeStatus;
}

// functor object type for find_if:
struct FieldsMatch {
	bool operator()(std::pair<CUUID, CItemData> p) {
		const CItemData &item = p.second;
		return (m_group == item.GetGroup() &&
			m_title == item.GetTitle() &&
			m_user == item.GetUser());
	}
	FieldsMatch(const StringX &a_group, const StringX &a_title,
		const StringX &a_user) :
		m_group(a_group), m_title(a_title), m_user(a_user) {}

private:
	FieldsMatch& operator=(const FieldsMatch&); // Do not implement
	const StringX &m_group;
	const StringX &m_title;
	const StringX &m_user;
};

// Finds stuff based on group, title & user fields only
ItemListIter PWScore::Find(const StringX &a_group, const StringX &a_title,
	const StringX &a_user)
{
	FieldsMatch fields_match(a_group, a_title, a_user);

	ItemListIter retval = find_if(m_pwlist.begin(), m_pwlist.end(),
		fields_match);
	return retval;
}

/*
*  Start UI Interface feedback routines
*/

void PWScore::NotifyDBModified()
{
	// This allows the core to provide feedback to the UI that the Database
	// has changed particularly to invalidate any current Find results and
	// to populate message during Vista and later shutdowns
	if (m_bNotifyDB && m_pUIIF != NULL &&
		m_bsSupportedFunctions.test(UIInterFace::DATABASEMODIFIED))
		m_pUIIF->DatabaseModified(m_bDBChanged || m_bDBPrefsChanged);
}



