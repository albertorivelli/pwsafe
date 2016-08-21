//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "App.xaml.h"
#include "MainPage.xaml.h"

using namespace pwsafe;

using namespace concurrency;
using namespace Platform;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Navigation;

MainPage::MainPage()
{
	InitializeComponent();
}

void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	StringX pass;
	pass.append(L"ciao");

	int rc2 = m_core.ReadCurFile(pass, true, 30000);

	//for (auto listPos = m_core.GetEntryIter(); listPos != m_core.GetEntryEndIter();
	//	listPos++) {
	//	CItemData &ci = m_core.GetEntry(listPos);
	//	DisplayInfo *pdi = (DisplayInfo *)ci.GetDisplayInfo();
	//	if (pdi != NULL)
	//		pdi->list_index = -1; // easier, but less efficient, to delete pdi
	//	InsertItemIntoGUITreeList(ci, -1, false, iView);
	//}

	//// Need to add any empty groups into the view
	//for (auto &emptyGrp : m_core.GetEmptyGroups()) {
	//	bool bAlreadyExists;
	//	m_ctlItemTree.AddGroup(emptyGrp.c_str(), bAlreadyExists);
	//}

	//m_ctlItemTree.SortTree(TVI_ROOT);
	//SortListView();
}

