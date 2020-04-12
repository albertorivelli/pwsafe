//
// MainPage.xaml.h
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"
#include <pplawait.h>
#include <collection.h>

using namespace concurrency;
using namespace Platform;
using namespace Platform::Collections;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml::Interop;

namespace pwsafe
{
	[Windows::UI::Xaml::Data::Bindable]
	public ref class ItemEntry sealed : Windows::UI::Xaml::Data::INotifyPropertyChanged
	{
	private:
		Platform::Boolean changed;
		Platform::Boolean isnew;
		Platform::String^ group;
		Platform::String^ title;
		Platform::String^ user;
		Platform::String^ password;
		Platform::String^ notes;
		Platform::String^ url;
		Platform::String^ email;
		Platform::String^ symbols;
		CItemData *original;
	internal:
		ItemEntry(CItemData *ci) {
			if (ci != NULL) {
				original = ci;
				changed = false;
				isnew = false;
				group = ref new String(ci->GetGroup().data());
				title = ref new String(ci->GetTitle().data());
				user = ref new String(ci->GetUser().data());
				password = ref new String(ci->GetPassword().data());
				notes = ref new String(ci->GetNotes().data());
				url = ref new String(ci->GetURL().data());
				email = ref new String(ci->GetEmail().data());
				symbols = ref new String(ci->GetSymbols().data());
			}
		}

		ItemEntry(ItemEntry^ ie) {
			if (ie != nullptr) {
				original = ie->original;
				changed = ie->changed;
				isnew = ie->isnew;
				group = ie->group;
				title = ie->title;
				user = ie->user;
				password = ie->password;
				notes = ie->notes;
				url = ie->url;
				email = ie->email;
				symbols = ie->symbols;
			}
		}
	public:
		virtual event Windows::UI::Xaml::Data::PropertyChangedEventHandler^ PropertyChanged;

		property Platform::Boolean HasChanged
		{
			Platform::Boolean get() { return this->changed; };
			void set(Platform::Boolean value) { this->changed = value; };
		}

		property Platform::Boolean IsNew
		{
			Platform::Boolean get() { return this->isnew; };
			void set(Platform::Boolean value) { this->isnew = value; };
		}

		property int GetOriginalCI
		{
			int get() { return (int)this->original; };
		}

		property Platform::String^ Group
		{
			Platform::String^ get() { return this->group; }
			void set(Platform::String^ value) {
				if (group != value)
				{
					group = value;
					original->SetGroup(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Group");
				}
			}
		}
		property Platform::String^ Title
		{
			Platform::String^ get() { return this->title; }
			void set(Platform::String^ value) {
				if (title != value)
				{
					title = value;
					original->SetTitle(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Title");
				}
			}
		}
		property Platform::String^ User
		{
			Platform::String^ get() { return this->user; }
			void set(Platform::String^ value) {
				if (user != value)
				{
					user = value;
					original->SetUser(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("User");
				}
			}
		}
		property Platform::String^ Password
		{
			Platform::String^ get() { return this->password; }
			void set(Platform::String^ value) {
				if (password != value)
				{
					password = value;
					original->SetPassword(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Password");
				}
			}
		}
		property Platform::String^ Notes
		{
			Platform::String^ get() { return this->notes; }
			void set(Platform::String^ value) {
				if (notes != value)
				{
					notes = value;
					original->SetNotes(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Notes");
				}
			}
		}
		property Platform::String^ Url
		{
			Platform::String^ get() { return this->url; }
			void set(Platform::String^ value) {
				if (url != value)
				{
					url = value;
					original->SetURL(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Url");
				}
			}
		}
		property Platform::String^ Email
		{
			Platform::String^ get() { return this->email; }
			void set(Platform::String^ value) {
				if (email != value)
				{
					email = value;
					original->SetEmail(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Email");
				}
			}
		}
		property Platform::String^ Symbols
		{
			Platform::String^ get() { return this->symbols; }
			void set(Platform::String^ value) {
				if (symbols != value)
				{
					symbols = value;
					original->SetSymbols(StringX(value->Data()));
					changed = true;
					OnPropertyChanged("Symbols");
				}
			}
		}
	private:
		void ItemEntry::OnPropertyChanged(String^ propertyName)
		{
			PropertyChanged(this, ref new Windows::UI::Xaml::Data::PropertyChangedEventArgs(propertyName));
		}
	};

	[Windows::UI::Xaml::Data::Bindable]
	public ref class ItemEntryGroup sealed {
	private:
		String^ key;
		IVector<ItemEntry^>^ items;
	public:
		property String^ Key
		{
			Platform::String^ get() { return this->key; }
			void set(Platform::String^ value) { key = value; }
		}

		property IVector<ItemEntry^>^ Items
		{
			IVector<ItemEntry^>^ get() { return this->items; }
			void set(IVector<ItemEntry^>^ value) { items = value; }
		}

	};

	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public ref class MainPage sealed
	{
	public:
		MainPage();
		property IVector<ItemEntryGroup^>^ ItemEntries
		{
			IVector<ItemEntryGroup^>^ get()
			{
				if (this->m_pwcollection == nullptr)
				{
					this->m_pwcollection = ref new Vector<ItemEntryGroup^>();
				}
				return this->m_pwcollection;
			};
		}
	private:
		task<void> NavigatedToHandler(String^ e);
		IVector<ItemEntryGroup^>^ m_pwcollection;
		ItemEntry ^ci_original, ^ci_edit;
	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;
	private:
		ItemEntryGroup^ Find(IVector<ItemEntryGroup^>^ v, String^ key);
		void lvItems_RightTapped(Platform::Object^ sender, Windows::UI::Xaml::Input::RightTappedRoutedEventArgs^ e);
		void lvItems_Holding(Platform::Object^ sender, Windows::UI::Xaml::Input::HoldingRoutedEventArgs^ e);
		void btnCopyUsername_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnCopyPassword_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnClearClipboard_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnItemAdd_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void lvItems_ItemClick(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e);
		void AddEntry();
		void UpdateEntry();
		enum ChangeType { Clear, Data, TimeStamp, DBPrefs, ClearDBPrefs };
		void SetChanged(ChangeType changed);
		enum SaveType {
			ST_INVALID = -1, ST_NORMALEXIT = 0,
			ST_ENDSESSIONEXIT, ST_WTSLOGOFFEXIT, ST_FAILSAFESAVE
		};
		task<int> Save(const SaveType savetype = ST_INVALID);
		task<int> SaveAs();
	};
}
