//
// ItemPage.xaml.h
// Declaration of the ItemPage class
//

#pragma once

#include "ItemPage.g.h"

namespace pwsafe
{
	[Windows::Foundation::Metadata::WebHostHidden]
	public ref class ItemPage sealed
	{
	public:
		ItemPage();
	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;
	private:
		void chkItemShowPassword_Checked(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void chkItemShowPassword_Unchecked(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void hlkItemUrl_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void hlkItemEmail_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
	};
}
