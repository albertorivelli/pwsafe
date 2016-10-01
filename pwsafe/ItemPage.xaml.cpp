//
// ItemPage.xaml.cpp
// Implementation of the ItemPage class
//

#include "pch.h"
#include "ItemPage.xaml.h"
#include "MainPage.xaml.h"

using namespace pwsafe;

using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;

ItemPage::ItemPage()
{
	InitializeComponent();
}

void ItemPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	Page::OnNavigatedTo(e);

	auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);
	if (rootFrame->CanGoBack)
	{
		Windows::UI::Core::SystemNavigationManager::GetForCurrentView()->AppViewBackButtonVisibility =
			Windows::UI::Core::AppViewBackButtonVisibility::Visible;
	}
	else
	{
		Windows::UI::Core::SystemNavigationManager::GetForCurrentView()->AppViewBackButtonVisibility =
			Windows::UI::Core::AppViewBackButtonVisibility::Collapsed;
	}

	this->DataContext = nullptr;

	ItemEntry^ s = (ItemEntry^)e->Parameter;
	this->DataContext = s;
}

void pwsafe::ItemPage::chkItemShowPassword_Checked(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	txtItemPassword->PasswordRevealMode = PasswordRevealMode::Visible;
	txtItemPasswordConfirm->IsEnabled = false;
}

void pwsafe::ItemPage::chkItemShowPassword_Unchecked(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	txtItemPassword->PasswordRevealMode = PasswordRevealMode::Hidden;
	txtItemPasswordConfirm->IsEnabled = true;
}


void pwsafe::ItemPage::hlkItemUrl_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	Windows::System::Launcher::LaunchUriAsync(ref new Uri("http://" + hlkItemUrl->Content->ToString()));
}


void pwsafe::ItemPage::hlkItemEmail_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	Windows::System::Launcher::LaunchUriAsync(ref new Uri("mailto:" + hlkItemEmail->Content->ToString()));
}
