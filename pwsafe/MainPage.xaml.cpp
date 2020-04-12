//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "App.xaml.h"
#include "MainPage.xaml.h"
#include "ItemPage.xaml.h"

using namespace pwsafe;

using namespace concurrency;
using namespace Platform;
using namespace Windows::ApplicationModel::DataTransfer;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Navigation;

MainPage::MainPage()
{
	InitializeComponent();
	this->NavigationCacheMode = Windows::UI::Xaml::Navigation::NavigationCacheMode::Enabled;
}

void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	Windows::UI::Core::SystemNavigationManager::GetForCurrentView()->AppViewBackButtonVisibility =
		Windows::UI::Core::AppViewBackButtonVisibility::Collapsed;

	auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);
	if (rootFrame != nullptr)
	{
		rootFrame->BackStack->Clear();
	}

	if (e->NavigationMode == NavigationMode::Back)
	{
		if (ci_edit != nullptr && ci_edit->HasChanged)
		{
			if (ci_edit->IsNew)
			{
				AddEntry();
			}
			else
			{
				UpdateEntry();
			}
		}
		ci_edit = nullptr;
		return;
	}

	String^ s = (String^)e->Parameter;
	NavigatedToHandler(s);
}

bool CompareItems(ItemEntry^ i1, ItemEntry^ i2)
{
	return _wcsicmp(i1->Title->Data(), i2->Title->Data()) < 0;
}

bool CompareItemGroups(ItemEntryGroup^ g1, ItemEntryGroup^ g2)
{
	return String::CompareOrdinal(g1->Key, g2->Key) < 0;
}

task<void> MainPage::NavigatedToHandler(String^ s)
{
	progressItems->IsActive = true;

	StringX pass(s->Data());

	int rc2 = co_await m_core.ReadCurFile(pass, true, 30000);

	for (auto listPos = m_core.GetEntryIter(); listPos != m_core.GetEntryEndIter(); listPos++)
	{
		CItemData &ci = m_core.GetEntry(listPos);
		ItemEntry^ t = ref new ItemEntry(&ci);

		auto iter = t->Title->Begin();
		wchar_t letter[1];
		letter[0] = towupper(iter[0]);
		String^ l = ref new String(letter, 1);

		auto group = Find(ItemEntries, l);
		if (group != nullptr) {
			group->Items->Append(t);
		}
		else {
			auto g = ref new ItemEntryGroup();
			g->Key = l;
			g->Items = ref new Vector<ItemEntry^>();
			g->Items->Append(t);

			ItemEntries->Append(g);
		}
	}

	// extremely inefficient it's better to insert in order above
	std::sort(begin(ItemEntries), end(ItemEntries), CompareItemGroups);

	// extremely inefficient it's better to insert in order above
	auto iterator = ItemEntries->First();
	while (iterator->HasCurrent)
	{
		auto group = iterator->Current;

		std::sort(begin(group->Items), end(group->Items), CompareItems);

		iterator->MoveNext();
	}

	cvsLetters->Source = ItemEntries;

	progressItems->IsActive = false;

	//// Need to add any empty groups into the view
	//for (auto &emptyGrp : m_core.GetEmptyGroups()) {
	//	bool bAlreadyExists;
	//	m_ctlItemTree.AddGroup(emptyGrp.c_str(), bAlreadyExists);
	//}

	//m_ctlItemTree.SortTree(TVI_ROOT);
	//SortListView();
}

ItemEntryGroup^ MainPage::Find(Windows::Foundation::Collections::IVector<ItemEntryGroup^>^ v, String^ k)
{
	ItemEntryGroup^ ret = nullptr;

	auto iterator = v->First();
	while (iterator->HasCurrent)
	{
		auto item = iterator->Current;
		if (item->Key == k)
		{
			ret = item;
			break;
		}

		iterator->MoveNext();
	}

	return ret;
}

void pwsafe::MainPage::lvItems_RightTapped(Platform::Object^ sender, Windows::UI::Xaml::Input::RightTappedRoutedEventArgs^ e)
{
	if (e->PointerDeviceType == Windows::Devices::Input::PointerDeviceType::Mouse)
	{
		auto item = ((FrameworkElement^)e->OriginalSource)->DataContext;

		if (item != nullptr)
		{
			lvItems->SelectedItem = item;

			ContextFlyout->ShowAt((FrameworkElement^)sender, e->GetPosition((FrameworkElement^)sender));

			e->Handled = true;
		}
	}
}

void pwsafe::MainPage::lvItems_Holding(Platform::Object^ sender, Windows::UI::Xaml::Input::HoldingRoutedEventArgs^ e)
{
	if (e->HoldingState == Windows::UI::Input::HoldingState::Started)
	{
		auto item = ((FrameworkElement^)e->OriginalSource)->DataContext;

		if (item != nullptr)
		{
			lvItems->SelectedItem = item;

			ContextFlyout->ShowAt((FrameworkElement^)sender, e->GetPosition((FrameworkElement^)sender));

			e->Handled = true;
		}
	}
}

void pwsafe::MainPage::btnCopyUsername_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	auto item = (ItemEntry^)lvItems->SelectedItem;

	if (item != nullptr)
	{
		auto dataPackage = ref new DataPackage();

		// Set the content as CF_TEXT text format.
		dataPackage->SetText(item->User);

		try
		{
			// Set the contents in the clipboard
			Clipboard::SetContent(dataPackage);
		}
		catch (Exception^ ex)
		{
			// Copying data to the Clipboard can potentially fail - for example, if another application is holding the Clipboard open
		}
	}
}

void pwsafe::MainPage::btnCopyPassword_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	auto item = (ItemEntry^)lvItems->SelectedItem;

	if (item != nullptr)
	{
		auto dataPackage = ref new DataPackage();

		// Set the content as CF_TEXT text format.
		dataPackage->SetText(item->Password);

		try
		{
			// Set the contents in the clipboard
			Clipboard::SetContent(dataPackage);
		}
		catch (Exception^ ex)
		{
			// Copying data to the Clipboard can potentially fail - for example, if another application is holding the Clipboard open
		}
	}
}

void pwsafe::MainPage::btnClearClipboard_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	try
	{
		// Set the contents in the clipboard
		Clipboard::Clear();
	}
	catch (Exception^ ex)
	{
		// Copying data to the Clipboard can potentially fail - for example, if another application is holding the Clipboard open
	}
}

void pwsafe::MainPage::btnItemAdd_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	CItemData* ci = new CItemData();
	ci->CreateUUID();

	ci_edit = ref new ItemEntry(ci);
	ci_edit->IsNew = true;

	if (ci_edit != nullptr)
	{
		auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);
		if (rootFrame != nullptr)
		{
			rootFrame->Navigate(TypeName(ItemPage::typeid), ci_edit);
		}
	}
}

void pwsafe::MainPage::lvItems_ItemClick(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e)
{
	// Note that Edit is also used for just viewing - don't want to disable
	// viewing in read-only mode
	//if (SelItemOk() == TRUE) {
	//	CItemData *pci = getSelectedItem();
	//	ASSERT(pci != NULL);
	if (e->ClickedItem != nullptr)
	{
		//	try {
		//		if (pci->IsShortcut()) {
		//			if (!m_bViaDCA) {
		//				EditShortcut(pci);
		//			}
		//			else {
		//				EditItem(GetBaseEntry(pci));
		//			}
		//		}
		//		else {
		//			EditItem(pci);
		//		}
		//	}
		//	catch (CString &err) {
		//		CGeneralMsgBox gmb;
		//		gmb.MessageBox(err, NULL, MB_OK | MB_ICONERROR);
		//	}

		// void Edititem(){
		// Note: In all but one circumstance, pcore == NULL, implying edit of an entry
		// in the current database.
		// The one exception is when the user wishes to View an entry from the comparison
		// database via "CompareResultsDlg" (the Compare Database results dialog).
		// Note: In this instance, the comparison database is R-O and hence the user may
		// only View these entries and any database preferences can be obtain from the
		// copy of the header within that instance of PWScore - see below when changing the
		// default username.
		//if (pcore == NULL)
			//pcore = &m_core;

		ci_original = (ItemEntry^)e->ClickedItem;

		ci_edit = ref new ItemEntry(ci_original);

		//	CItemData ci_edit(*pci);
		//
		//	// As pci may be invalidated if database is Locked while in this routine,
		//	// we use a clone
		//	CItemData ci_original(*pci);
		//	pci = NULL; // Set to NULL - should use ci_original
		//
		//	const UINT uicaller = pcore->IsReadOnly() ? IDS_VIEWENTRY : IDS_EDITENTRY;
		//
		//	// List might be cleared if db locked.
		//	// Need to take care that we handle a rebuilt list.
		//	bool bIsDefUserSet;
		//	StringX sxDefUserValue;
		//	PWSprefs *prefs = PWSprefs::GetInstance();
		//	if (pcore == &m_core) {
		//		// As it is us, get values from actually current
		//		bIsDefUserSet = prefs->GetPref(PWSprefs::UseDefaultUser) ? TRUE : FALSE;
		//		sxDefUserValue = prefs->GetPref(PWSprefs::DefaultUsername);
		//	}
		//	else {
		//		// Need to get Default User value from this core's preferences stored in its header.
		//		// Since this core is R-O, the values in the header will not have been changed
		//		StringX sxDBPreferences(pcore->GetDBPreferences());
		//		prefs->GetDefaultUserInfo(sxDBPreferences, bIsDefUserSet, sxDefUserValue);
		//	}
		//
		//	CAddEdit_PropertySheet *pEditEntryPSH(NULL);
		//
		//	// Try Tall version
		//	pEditEntryPSH = new CAddEdit_PropertySheet(uicaller, this, pcore,
		//		&ci_original, &ci_edit,
		//		true, pcore->GetCurFile());
		//
		//	if (bIsDefUserSet)
		//		pEditEntryPSH->SetDefUsername(sxDefUserValue.c_str());
		//
		//	// Don't show Apply button if in R-O mode (View)
		//	if (uicaller == IDS_VIEWENTRY)
		//		pEditEntryPSH->m_psh.dwFlags |= PSH_NOAPPLYNOW;

		auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);
		if (rootFrame != nullptr)
		{
			//	INT_PTR rc = pEditEntryPSH->DoModal();

			rootFrame->Navigate(TypeName(ItemPage::typeid), ci_edit);

			//	bool brc(false);
			//	if (rc == IDOK && uicaller == IDS_EDITENTRY && pEditEntryPSH->IsEntryModified()) {
			//		// Process user's changes.
			//		UpdateEntry(pEditEntryPSH);
			//		brc = true;
			//	} // rc == IDOK

			//	  // Delete Edit Entry Property Sheet
			//	delete pEditEntryPSH;
			//	return brc;
		}
	}
	else {
		//	// entry item not selected - perhaps here on Enter on tree item?
		//	// perhaps not the most elegant solution to improving non-mouse use,
		//	// but it works. If anyone knows how Enter/Return gets mapped to OnEdit,
		//	// let me know...
		//	if (m_ctlItemTree.IsWindowVisible()) { // tree view
		//		HTREEITEM ti = m_ctlItemTree.GetSelectedItem();
		//		if (ti != NULL) { // if anything selected
		//			CItemData *pci_node = (CItemData *)m_ctlItemTree.GetItemData(ti);
		//			if (pci_node == NULL) { // node selected
		//				m_ctlItemTree.Expand(ti, TVE_TOGGLE);
		//			}
		//		}
		//	}
	}
}

void pwsafe::MainPage::AddEntry()
{
	bool bWasEmpty = m_core.GetNumEntries() == 0;
	bool bSetDefaultUser(false);

	MultiCommands *pmulticmds = MultiCommands::Create(&m_core);

	CItemData ci(*((CItemData *)(ci_edit->GetOriginalCI)));

	// Save to find it again
	const pws_os::CUUID newentry_uuid = ci.GetUUID();

	// Add the entry
	ci.SetStatus(CItemData::ES_ADDED);
	StringX sxGroup = ci.GetGroup();
	if (m_core.IsEmptyGroup(sxGroup)) {
		// It was an empty group - better delete it
		pmulticmds->Add(DBEmptyGroupsCommand::Create(&m_core, sxGroup,
			DBEmptyGroupsCommand::EG_DELETE));
	}

	pws_os::CUUID baseUUID(pws_os::CUUID::NullUUID());
	//if (pAddEntryPSH->GetIBasedata() != 0)  // creating an alias
	//	baseUUID = pAddEntryPSH->GetBaseUUID();

	pmulticmds->Add(AddEntryCommand::Create(&m_core, ci, baseUUID));

	if (bSetDefaultUser) {
		Command *pcmd3 = UpdateGUICommand::Create(&m_core,
			UpdateGUICommand::WN_EXECUTE_REDO,
			UpdateGUICommand::GUI_REFRESH_TREE);
		pmulticmds->Add(pcmd3);
	}

	m_core.Execute(pmulticmds);

	//if (m_core.GetNumEntries() == 1) {
	//	// For some reason, when adding the first entry, it is not visible!
	//	m_ctlItemTree.SetRedraw(TRUE);
	//}

	//SortListView();
	//m_ctlItemList.SetFocus();
	SetChanged(Data);

	// Find the new entry again as DisplayInfo now updated
	ItemListIter iter = m_core.Find(newentry_uuid);
	//UpdateToolBarForSelectedItem(&iter->second);

	//ChangeOkUpdate();
	//m_RUEList.AddRUEntry(newentry_uuid);

	//// May need to update menu/toolbar if database was previously empty
	//if (bWasEmpty)
	//	UpdateMenuAndToolBar(m_bOpen);

	//if (m_ctlItemTree.IsWindowVisible())
	//	m_ctlItemTree.SetFocus();
	//else
	//	m_ctlItemList.SetFocus();
	CItemData &ci2 = m_core.GetEntry(iter);
	ItemEntry^ t = ref new ItemEntry(&ci2);

	auto title = ci_edit->Title->Begin();
	wchar_t letter[1];
	letter[0] = towupper(title[0]);
	String^ l = ref new String(letter, 1);

	auto group = Find(ItemEntries, l);
	if (group != nullptr) {
		group->Items->Append(ci_edit);
	}
	else {
		auto g = ref new ItemEntryGroup();
		g->Key = l;
		g->Items = ref new Vector<ItemEntry^>();
		g->Items->Append(ci_edit);

		ItemEntries->Append(g);
	}
}

//LRESULT DboxMain::OnApplyEditChanges(WPARAM wParam, LPARAM lParam)
//{
//	// Called if user does 'Apply' on the Add/Edit property sheet via
//	// Windows Message PWS_MSG_EDIT_APPLY
//	UNREFERENCED_PARAMETER(lParam);
//	CAddEdit_PropertySheet *pentry_psh = (CAddEdit_PropertySheet *)wParam;
//	UpdateEntry(pentry_psh);
//	return 0L;
//}
//
//void pwsafe::MainPage::UpdateEntry(CAddEdit_PropertySheet *pentry_psh)
void pwsafe::MainPage::UpdateEntry()
{
	// Called by EditItem on return from Edit but
	// also called if user does 'Apply' on the Add/Edit property sheet via
	// Windows Message PWS_MSG_EDIT_APPLY
	
	PWScore *pcore = &m_core;
	const CItemData *pci_original = (CItemData *)(ci_original->GetOriginalCI);
	CItemData ci_new(*((CItemData *)(ci_edit->GetOriginalCI)));
	
	// Most of the following code handles special cases of alias/shortcut/base
	// But the common case is simply to replace the original entry
	// with a new one having the edited values and the same uuid.
	MultiCommands *pmulticmds = MultiCommands::Create(pcore);
	Command *pcmd(NULL);
	
	StringX newPassword = ci_new.GetPassword();
	
	pws_os::CUUID original_base_uuid = pws_os::CUUID::NullUUID();
	pws_os::CUUID new_base_uuid;
	pws_os::CUUID original_uuid = pci_original->GetUUID();
	
	if (pci_original->IsDependent()) {
		const CItemData *pci_orig_base = m_core.GetBaseEntry(pci_original);
		ASSERT(pci_orig_base != NULL);
		original_base_uuid = pci_orig_base->GetUUID();
	}
	
	//ItemListIter iter;
	//if (pentry_psh->GetOriginalEntrytype() == CItemData::ET_NORMAL &&
	//	pci_original->GetPassword() != newPassword) {
	//	// Original was a 'normal' entry and the password has changed
	//	if (pentry_psh->GetIBasedata() > 0) { // Now an alias
	//		pcmd = AddDependentEntryCommand::Create(pcore, new_base_uuid,
	//			original_uuid,
	//			CItemData::ET_ALIAS);
	//		pmulticmds->Add(pcmd);
	//		ci_new.SetPassword(L"[Alias]");
	//		ci_new.SetAlias();
	//		ci_new.SetBaseUUID(new_base_uuid);
	//	}
	//	else { // Still 'normal'
	//		ci_new.SetPassword(newPassword);
	//		ci_new.SetNormal();
	//	}
	//} // Normal entry, password changed
	//
	//if (pentry_psh->GetOriginalEntrytype() == CItemData::ET_ALIAS) {
	//	// Original was an alias - delete it from multimap
	//	// RemoveDependentEntry also resets base to normal if no more dependents
	//	pcmd = RemoveDependentEntryCommand::Create(pcore, original_base_uuid,
	//		original_uuid,
	//		CItemData::ET_ALIAS);
	//	pmulticmds->Add(pcmd);
	//	if (newPassword == pentry_psh->GetBase()) {
	//		// Password (i.e. base) unchanged - put it back
	//		pcmd = AddDependentEntryCommand::Create(pcore, original_base_uuid,
	//			original_uuid,
	//			CItemData::ET_ALIAS);
	//		pmulticmds->Add(pcmd);
	//	}
	//	else { // Password changed
	//			// Password changed so might be an alias of another entry!
	//			// Could also be the same entry i.e. [:t:] == [t] !
	//		if (pentry_psh->GetIBasedata() > 0) { // Still an alias
	//			pcmd = AddDependentEntryCommand::Create(pcore, new_base_uuid,
	//				original_uuid,
	//				CItemData::ET_ALIAS);
	//			pmulticmds->Add(pcmd);
	//			ci_new.SetPassword(L"[Alias]");
	//			ci_new.SetAlias();
	//			ci_new.SetBaseUUID(new_base_uuid);
	//		}
	//		else { // No longer an alias
	//			ci_new.SetPassword(newPassword);
	//			ci_new.SetNormal();
	//		}
	//	} // Password changed
	//} // Alias
	//
	//if (pentry_psh->GetOriginalEntrytype() == CItemData::ET_ALIASBASE &&
	//	pci_original->GetPassword() != newPassword) {
	//	// Original was a base but might now be an alias of another entry!
	//	if (pentry_psh->GetIBasedata() > 0) {
	//		// Now an alias
	//		// Make this one an alias
	//		pcmd = AddDependentEntryCommand::Create(pcore, new_base_uuid,
	//			original_uuid,
	//			CItemData::ET_ALIAS);
	//		pmulticmds->Add(pcmd);
	//		ci_new.SetPassword(L"[Alias]");
	//		ci_new.SetAlias();
	//		ci_new.SetBaseUUID(new_base_uuid);
	//		// Move old aliases across
	//		pcmd = MoveDependentEntriesCommand::Create(pcore, original_uuid,
	//			new_base_uuid,
	//			CItemData::ET_ALIAS);
	//		pmulticmds->Add(pcmd);
	//	}
	//	else { // Still a base entry but with a new password
	//		ci_new.SetPassword(newPassword);
	//		ci_new.SetAliasBase();
	//	}
	//} // AliasBase with password changed
	//
	//	// Update old base...
	//iter = pcore->Find(original_base_uuid);
	//if (iter != End())
	//	UpdateEntryImages(iter->second);
	//
	//// ... and the new base entry (only if different from the old one)
	//if (pws_os::CUUID(new_base_uuid) != pws_os::CUUID(original_base_uuid)) {
	//	iter = pcore->Find(new_base_uuid);
	//	if (iter != End())
	//		UpdateEntryImages(iter->second);
	//}
	//
	//if (ci_new.IsDependent()) {
	//	ci_new.SetXTime((time_t)0);
	//	ci_new.SetPWPolicy(L"");
	//}
	
	ci_new.SetStatus(CItemData::ES_MODIFIED);
	
	pcmd = EditEntryCommand::Create(pcore, *(pci_original), ci_new);
	pmulticmds->Add(pcmd);
	
	const StringX &sxNewGroup = ci_new.GetGroup();
	if (m_core.IsEmptyGroup(sxNewGroup)) {
		// It was an empty group - better delete it
		pmulticmds->Add(DBEmptyGroupsCommand::Create(&m_core, sxNewGroup,
			DBEmptyGroupsCommand::EG_DELETE));
	}
	
	pcore->Execute(pmulticmds);

	SetChanged(Data);
	//ChangeOkUpdate();
	//
	//// Order may have changed as a result of edit
	//m_ctlItemTree.SortTree(TVI_ROOT);
	//SortListView();
	//
	//short sh_odca, sh_ndca;
	//pci_original->GetDCA(sh_odca);
	//ci_new.GetDCA(sh_ndca);
	//if (sh_odca != sh_ndca)
	//	SetDCAText(&ci_new);
	//
	//UpdateToolBarForSelectedItem(&ci_new);
	//
	//// Password may have been updated and so not expired
	//UpdateEntryImages(ci_new);
	//
	//// Update display if no longer passes filter criteria
	//if (m_bFilterActive &&
	//	!m_FilterManager.PassesFiltering(ci_new, m_core)) {
	//	RefreshViews();
	//	return;
	//}
	//
	//// Reselect entry, where-ever it may be
	//iter = m_core.Find(original_uuid);
	//if (iter != End()) {
	//	DisplayInfo *pdi = (DisplayInfo *)iter->second.GetDisplayInfo();
	//	SelectEntry(pdi->list_index);
	//}

	auto title = ci_original->Title->Begin();
	wchar_t letter[1];
	letter[0] = towupper(title[0]);
	String^ l = ref new String(letter, 1);
	auto title_edit = ci_edit->Title->Begin();
	wchar_t letter_edit[1];
	letter_edit[0] = towupper(title_edit[0]);
	String^ l_edit = ref new String(letter_edit, 1);

	if (l == l_edit)
	{
		auto group = Find(ItemEntries, l);
		if (group != nullptr)
		{
			unsigned int index;
			group->Items->IndexOf(ci_original, &index);
			group->Items->RemoveAt(index);
			group->Items->Append(ci_edit);
			std::sort(begin(group->Items), end(group->Items), CompareItems);
		}
	}
	else
	{
		auto group = Find(ItemEntries, l);
		auto group_edit = Find(ItemEntries, l_edit);
		if (group != nullptr) {
			unsigned int index;
			group->Items->IndexOf(ci_original, &index);
			group->Items->RemoveAt(index);
			if (group->Items->Size == 0)
			{
				ItemEntries->IndexOf(group, &index);
				ItemEntries->RemoveAt(index);
			}
		}
		if (group_edit != nullptr)
		{
			group->Items->Append(ci_edit);
			std::sort(begin(group->Items), end(group->Items), CompareItems);
		}
		else {
			auto g = ref new ItemEntryGroup();
			g->Key = l;
			g->Items = ref new Vector<ItemEntry^>();
			g->Items->Append(ci_edit);

			ItemEntries->Append(g);
		}
	}
}

void pwsafe::MainPage::SetChanged(ChangeType changed)
{
	//PWS_LOGIT_ARGS("changed=%d", changed);

	if (m_core.IsReadOnly())
		return;

	switch (changed)
	{
	case Data:
		if (/*PWSprefs::GetInstance()->GetPref(PWSprefs::SaveImmediately) && */m_core.GetReadFileVersion() == PWSfile::VCURRENT)
		{
			// Also save if adding group as it will be in the empty group list!
			// Or if not the current version of the DB
			Save();
		}
		else {
			m_core.SetDBChanged(true);
		}
		break;
	case Clear:
		m_core.SetChanged(false, false);
		//m_bTSUpdated = false;
		break;
	case TimeStamp:
		/*if (PWSprefs::GetInstance()->GetPref(PWSprefs::MaintainDateTimeStamps))
			m_bTSUpdated = true;*/
		break;
	case DBPrefs:
		m_core.SetDBPrefsChanged(true);
		break;
	case ClearDBPrefs:
		m_core.SetDBPrefsChanged(false);
		break;
	default:
		ASSERT(0);
	}
}

task<int> pwsafe::MainPage::Save(const SaveType savetype)
{
	/*
	* We're treating both V3 and V4 as 'current'
	* versions, doing incremental backups for both.
	* For older versions, we offer to convert.
	* This means explicit V3 -> V4 conversion
	* Is done via SaveAs()
	*/
	//PWS_LOGIT_ARGS("savetype=%d", savetype);

	int rc;
	/*CString cs_msg, cs_temp;
	CGeneralMsgBox gmb;*/
	std::wstring NewName;
	stringT bu_fname; // used to undo backup if save failed

	const StringX sxCurrFile = m_core.GetCurFile();
	const PWSfile::VERSION current_version = m_core.GetReadFileVersion();

	//PWSprefs *prefs = PWSprefs::GetInstance();
	//
	//// chdir to exe dir, avoid hassle with relative paths
	//PWSdirs dir(PWSdirs::GetExeDir()); // changes back in d'tor
	//
	//								   // Save Application related preferences
	//prefs->SaveApplicationPreferences();
	//prefs->SaveShortcuts();

	if (sxCurrFile.empty())
		return co_await SaveAs();

	switch (current_version) {
	case PWSfile::V30:
	case PWSfile::V40:
		//if (prefs->GetPref(PWSprefs::BackupBeforeEverySave)) {
		//	int maxNumIncBackups = prefs->GetPref(PWSprefs::BackupMaxIncremented);
		//	int backupSuffix = prefs->GetPref(PWSprefs::BackupSuffix);
		//	std::wstring userBackupPrefix = prefs->GetPref(PWSprefs::BackupPrefixValue).c_str();
		//	std::wstring userBackupDir = prefs->GetPref(PWSprefs::BackupDir).c_str();
		//	if (!m_core.BackupCurFile(maxNumIncBackups, backupSuffix,
		//		userBackupPrefix, userBackupDir, bu_fname)) {
		//		switch (savetype) {
		//		case ST_NORMALEXIT:
		//		{
		//			cs_temp.LoadString(IDS_NOIBACKUP);
		//			cs_msg.Format(IDS_NOIBACKUP2, cs_temp);
		//			gmb.SetTitle(IDS_FILEWRITEERROR);
		//			gmb.SetMsg(cs_msg);
		//			gmb.SetStandardIcon(MB_ICONEXCLAMATION);
		//			gmb.AddButton(IDS_SAVEAS, IDS_SAVEAS);
		//			gmb.AddButton(IDS_EXIT, IDS_EXIT, TRUE, TRUE);
		//
		//			if (gmb.DoModal() == IDS_EXIT)
		//				return PWScore::SUCCESS;
		//			else
		//				return SaveAs();
		//		}
		//
		//		case ST_INVALID:
		//			// No particular end of PWS exit i.e. user clicked Save or
		//			// saving a changed database before opening another
		//			gmb.AfxMessageBox(IDS_NOIBACKUP, MB_OK);
		//			return PWScore::USER_CANCEL;
		//
		//		default:
		//			break;
		//		}
		//		gmb.AfxMessageBox(IDS_NOIBACKUP, MB_OK);
		//		return SaveAs();
		//	} // BackupCurFile failed
		//} // BackupBeforeEverySave
		break;

		// Do NOT code the default case statement - each version value must be specified
		// Prior versions are always Read-Only and so Save is not appropriate - although
		// they can export to prior versions (no point if not changed) or SaveAs in the
		// current version format
	case PWSfile::V17:
	case PWSfile::V20:
	case PWSfile::NEWFILE:
	case PWSfile::UNKNOWN_VERSION:
		ASSERT(0);
		co_return (int)PWScore::FAILURE;
	} // switch on file version

	/*UUIDList RUElist;
	m_RUEList.GetRUEList(RUElist);
	m_core.SetRUEList(RUElist);*/

	// We are saving the current DB. Retain current version
	rc = co_await m_core.WriteFile(sxCurrFile, current_version);

	if (rc != PWScore::SUCCESS) { // Save failed!
		// Restore backup, if we have one
		//if (!bu_fname.empty() && !sxCurrFile.empty())
		//	pws_os::RenameFile(bu_fname, sxCurrFile.c_str());
		//// Show user that we have a problem
		//DisplayFileWriteError(rc, sxCurrFile);
		co_return rc;
	}

	m_core.ResetStateAfterSave();
	m_core.ResetOriginalGroupDisplayAfterSave();
	m_core.ClearChangedNodes();
	SetChanged(Clear);
	//ChangeOkUpdate();

	//// Added/Modified entries now saved - reverse it & refresh display
	//if (m_bUnsavedDisplayed)
	//	OnShowUnsavedEntries();

	//if (m_bFilterActive) { // we no longer limit this to status-changed filter
	//					   // although strictly speaking, we should (overhead doesn't seem worth it)
	//	m_ctlItemList.Invalidate();
	//	m_ctlItemTree.Invalidate();
	//}

	//// Only refresh views if not existing
	//if (savetype != ST_NORMALEXIT)
	//	RefreshViews();

	co_return PWScore::SUCCESS;
}

task<int> pwsafe::MainPage::SaveAs()
{
//	// SaveAs can only save in the current format
//	// To save as a lower or higher format, the user should use Export
//
//	// HOWEVER, in this "Experimental" version, V1.7, V2 & V3 DBs will be saved
//	// as V3 and only if the current DB is V4 will it be saved in V4 format.
//
//	//PWS_LOGIT;
//
//	INT_PTR rc;
//	StringX newfile;
//	String^ cs_msg, cs_title, cs_text, cs_temp;
//
//	const PWSfile::VERSION current_version = m_core.GetReadFileVersion();
//
//	// Only need to warn user if current DB is prior to V3 - no implications if saving V4 as V4 or V3 as V3
//	if (current_version < PWSfile::V30 &&
//		current_version != PWSfile::UNKNOWN_VERSION) {
//		//CGeneralMsgBox gmb;
//
//		//// Note: string IDS_NEWFORMAT2 will need to be updated when DB V4 is the default
//		//cs_msg.Format(IDS_NEWFORMAT2, m_core.GetCurFile().c_str());
//		//cs_title.LoadString(IDS_VERSIONWARNING);
//
//		//gmb.SetTitle(cs_title);
//		//gmb.SetMsg(cs_msg);
//		//gmb.SetStandardIcon(MB_ICONEXCLAMATION);
//		//gmb.AddButton(IDS_CONTINUE, IDS_CONTINUE);
//		//gmb.AddButton(IDS_CANCEL, IDS_CANCEL, TRUE, TRUE);
//
//		//if (gmb.DoModal() == IDS_CANCEL)
//			return PWScore::USER_CANCEL;
//	}
//
//	//SaveAs-type dialog box
//	StringX cf(m_core.GetCurFile());
//	if (cf.empty()) {
//		String^ defname = ref new String(MAKEINTRESOURCE(IDS_DEFDBNAME)); // reasonable default for first time user
//		cf = LPCWSTR(defname);
//	}
//
//	// Note: The default export DB will be V3 unless the current DB is already in V4 format
//	// This ensures that a user won't create an "Experimental" V4 DB by mistake
//	std::wstring newFileName = PWSUtil::GetNewFileName(cf.c_str(), current_version == PWSfile::V40 ? V4_SUFFIX : V3_SUFFIX);
//
//	std::wstring dir;
//	if (m_core.GetCurFile().empty())
//		dir = PWSdirs::GetSafeDir();
//	else {
//		std::wstring cdrive, cdir, dontCare;
//		pws_os::splitpath(m_core.GetCurFile().c_str(), cdrive, cdir, dontCare, dontCare);
//		dir = cdrive + cdir;
//	}
//
//	while (1) {
//		CPWFileDialog fd(FALSE,
//			current_version == PWSfile::V40 ? V4_SUFFIX : V3_SUFFIX,
//			newFileName.c_str(),
//			OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
//			OFN_LONGNAMES | OFN_OVERWRITEPROMPT,
//			CString(MAKEINTRESOURCE(current_version == PWSfile::V40 ? IDS_FDF_V4_ALL : IDS_FDF_V3_ALL)),
//			this);
//		if (m_core.GetCurFile().empty())
//			cs_text.LoadString(IDS_NEWNAME1);
//		else
//			cs_text.LoadString(IDS_NEWNAME2);
//
//		fd.m_ofn.lpstrTitle = cs_text;
//
//		if (!dir.empty())
//			fd.m_ofn.lpstrInitialDir = dir.c_str();
//
//		rc = fd.DoModal();
//
//		if (m_inExit) {
//			// If U3ExitNow called while in CPWFileDialog,
//			// PostQuitMessage makes us return here instead
//			// of exiting the app. Try resignalling
//			PostQuitMessage(0);
//			return PWScore::USER_CANCEL;
//		}
//		if (rc == IDOK) {
//			newfile = fd.GetPathName();
//			break;
//		}
//		else
//			return PWScore::USER_CANCEL;
//	}
//
//	std::wstring locker(L""); // null init is important here
//							  // Note: We have to lock the new file before releasing the old (on success)
//	if (!m_core.LockFile2(newfile.c_str(), locker)) {
//		CGeneralMsgBox gmb;
//		cs_temp.Format(IDS_FILEISLOCKED, newfile.c_str(), locker.c_str());
//		cs_title.LoadString(IDS_FILELOCKERROR);
//		gmb.MessageBox(cs_temp, cs_title, MB_OK | MB_ICONWARNING);
//		return PWScore::CANT_OPEN_FILE;
//	}
//
//	// Save file UUID, clear it to generate new one, restore if necessary
//	pws_os::CUUID file_uuid = m_core.GetFileUUID();
//	m_core.ClearFileUUID();
//
//	UUIDList RUElist;
//	m_RUEList.GetRUEList(RUElist);
//	m_core.SetRUEList(RUElist);
//
//	// Note: Writing out in in V4 DB format if the DB is already V4,
//	// otherwise as V3 (this include saving pre-3.0 DBs as a V3 DB!
//	rc = co_await m_core.WriteFile(newfile, current_version == PWSfile::V40 ? PWSfile::V40 : PWSfile::V30);
//	m_core.ResetStateAfterSave();
//	m_core.ResetOriginalGroupDisplayAfterSave();
//	m_core.ClearChangedNodes();
//
//	if (rc != PWScore::SUCCESS) {
//		m_core.SetFileUUID(file_uuid); // restore uuid after failed save-as
//		m_core.UnlockFile2(newfile.c_str());
//		DisplayFileWriteError(rc, newfile);
//		return PWScore::CANT_OPEN_FILE;
//	}
//	if (!m_core.GetCurFile().empty())
//		m_core.UnlockFile(m_core.GetCurFile().c_str());
//
//	// Move the newfile lock to the right place
//	m_core.MoveLock();
//
//	m_core.SetCurFile(newfile);
//	m_titlebar = PWSUtil::NormalizeTTT(L"Password Safe - " +
//		m_core.GetCurFile()).c_str();
//	SetWindowText(LPCWSTR(m_titlebar));
//	app.SetTooltipText(m_core.GetCurFile().c_str());
//	SetChanged(Clear);
//	ChangeOkUpdate();
//
//	// Added/Modified entries now saved - reverse it & refresh display
//	if (m_bUnsavedDisplayed)
//		OnShowUnsavedEntries();
//
//	if (m_bFilterActive) { // we no longer limit this to status-changed filter
//						   // although strictly speaking, we should (overhead doesn't seem worth it)
//		m_ctlItemList.Invalidate();
//		m_ctlItemTree.Invalidate();
//	}
//	RefreshViews();
//
//	app.AddToMRU(newfile.c_str());
//
//	if (m_core.IsReadOnly()) {
//		// reset read-only status (new file can't be read-only!)
//		// and so cause toolbar to be the correct version
//		m_core.SetReadOnly(false);
//	}
//
	co_return (int)PWScore::SUCCESS;
}

//int pwsafe::MainPage::SaveIfChanged()
//{
//	PWS_LOGIT;
//
//	/*
//	* Save silently (without asking user) iff:
//	* 1. NOT read-only AND
//	* 2. (timestamp updates OR tree view display vector changed) AND
//	* 3. Database NOT empty
//	*
//	* Less formally:
//	*
//	* If MaintainDateTimeStamps set and not read-only, save without asking
//	* user: "they get what it says on the tin".
//	*/
//
//	if (m_core.IsReadOnly())
//		return PWScore::SUCCESS;
//
//	// Note: RUE list saved here via time stamp being updated.
//	// Otherwise it won't be saved unless something else has changed
//	if ((m_bTSUpdated || m_core.WasDisplayStatusChanged()) &&
//		m_core.GetNumEntries() > 0) {
//		int rc = Save();
//		if (rc != PWScore::SUCCESS)
//			return PWScore::USER_CANCEL;
//		else
//			return PWScore::SUCCESS;
//	}
//
//	// offer to save existing database if it was modified.
//	// used before loading another
//	// returns PWScore::SUCCESS if save succeeded or if user decided
//	// not to save
//	if (m_core.IsChanged() || m_core.HaveDBPrefsChanged()) {
//		CGeneralMsgBox gmb;
//		INT_PTR rc, rc2;
//		CString cs_temp;
//		cs_temp.Format(IDS_SAVEDATABASE, m_core.GetCurFile().c_str());
//		rc = gmb.MessageBox(cs_temp, AfxGetAppName(),
//			MB_YESNOCANCEL | MB_ICONQUESTION);
//		switch (rc) {
//		case IDCANCEL:
//			return PWScore::USER_CANCEL;
//		case IDYES:
//			rc2 = Save();
//			// Make sure that file was successfully written
//			if (rc2 == PWScore::SUCCESS)
//				break;
//			else
//				return PWScore::CANT_OPEN_FILE;
//		case IDNO:
//			// It is a success but we need to know that the user said no!
//			return PWScore::USER_DECLINED_SAVE;
//		}
//	}
//	return PWScore::SUCCESS;
//}
