//
// PasskeyEntryPage.xaml.h
// Declaration of the PasskeyEntryPage class
//

#pragma once

#include "PasskeyEntryPage.g.h"
#include <pplawait.h>

using namespace pwsafe;

using namespace concurrency;
using namespace Platform;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Interop;
using namespace Windows::UI::Xaml::Navigation;

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

	private:
		StringX m_filespec;
		StringX m_passkey;
		void btnOpenFile_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		task<void> PickfileAsync();
		void btnOk_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		task<void> OkHandler();
		task<void> ProcessPhrase();
		task<int> CheckPasskey(const StringX &filename, const StringX &passkey, PWScore *pcore = NULL);

	};
}
