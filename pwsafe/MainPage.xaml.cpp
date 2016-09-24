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
	String^ s = (String^)e->Parameter;
	NavigatedToHandler(s);
}

bool CompareItems(ItemEntry^ i1, ItemEntry^ i2)
{
	return _wcsicmp(i1->Title->Data(), i2->Title->Data()) < 0;
}

task<void> MainPage::NavigatedToHandler(String^ s)
{
	StringX pass(s->Data());

	int rc2 = co_await m_core.ReadCurFile(pass, true, 30000);

	for (auto listPos = m_core.GetEntryIter(); listPos != m_core.GetEntryEndIter();
		listPos++) {
		CItemData &ci = m_core.GetEntry(listPos);
		ItemEntry^ t = ref new ItemEntry(ref new String(ci.GetTitle().data()), ref new String(ci.GetUser().data()), ref new String(ci.GetPassword().data()));
		ItemEntries->Append(t);
	}

	std::sort(begin(ItemEntries), end(ItemEntries), CompareItems);

	//// Need to add any empty groups into the view
	//for (auto &emptyGrp : m_core.GetEmptyGroups()) {
	//	bool bAlreadyExists;
	//	m_ctlItemTree.AddGroup(emptyGrp.c_str(), bAlreadyExists);
	//}

	//m_ctlItemTree.SortTree(TVI_ROOT);
	//SortListView();
}
