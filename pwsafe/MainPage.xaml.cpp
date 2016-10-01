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

	if (e->NavigationMode == NavigationMode::Back) return;

	String^ s = (String^)e->Parameter;
	NavigatedToHandler(s);
}

bool CompareItems(ItemEntry^ i1, ItemEntry^ i2)
{
	return _wcsicmp(i1->Title->Data(), i2->Title->Data()) < 0;
}

task<void> MainPage::NavigatedToHandler(String^ s)
{
	progressItems->IsActive = true;

	StringX pass(s->Data());

	int rc2 = co_await m_core.ReadCurFile(pass, true, 30000);

	for (auto listPos = m_core.GetEntryIter(); listPos != m_core.GetEntryEndIter();
		listPos++) {
		CItemData &ci = m_core.GetEntry(listPos);
		ItemEntry^ t = ref new ItemEntry(&ci);
		ItemEntries->Append(t);
	}

	std::sort(begin(ItemEntries), end(ItemEntries), CompareItems);

	progressItems->IsActive = false;

	//// Need to add any empty groups into the view
	//for (auto &emptyGrp : m_core.GetEmptyGroups()) {
	//	bool bAlreadyExists;
	//	m_ctlItemTree.AddGroup(emptyGrp.c_str(), bAlreadyExists);
	//}

	//m_ctlItemTree.SortTree(TVI_ROOT);
	//SortListView();
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

void pwsafe::MainPage::lvItems_ItemClick(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e)
{
	if (e->ClickedItem != nullptr)
	{
		auto i = (ItemEntry^)e->ClickedItem;

		auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);
		if (rootFrame != nullptr)
		{
			rootFrame->Navigate(TypeName(ItemPage::typeid), i);
		}
	}
}
