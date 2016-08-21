//
// PasskeyEntryPage.xaml.h
// Declaration of the PasskeyEntryPage class
//

#pragma once

#include "PasskeyEntryPage.g.h"

namespace pwsafe
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	[Windows::Foundation::Metadata::WebHostHidden]
	public ref class PasskeyEntryPage sealed
	{
	public:
		PasskeyEntryPage();
	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;

	private:
		StringX m_filespec;
		StringX m_passkey;
		void btnNew_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnOpenFile_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnOk_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void ProcessPhrase();
		int CheckPasskey(const StringX &filename, const StringX &passkey, PWScore *pcore = NULL);

	};
}
