//
// MainPage.xaml.h
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"
#include <pplawait.h>
#include <collection.h>

namespace pwsafe
{
	public ref class ItemEntry sealed
	{
	private:
		Platform::String^ title;
		Platform::String^ user;
		Platform::String^ password;
	public:
		ItemEntry(Platform::String^ title, Platform::String^ user, Platform::String^ password) :
			title{ title },
			user{ user },
			password{ password } {}

		property Platform::String^ Title
		{
			Platform::String^ get() { return this->title; }
		}
		property Platform::String^ User
		{
			Platform::String^ get() { return this->user; }
		}
		property Platform::String^ Password
		{
			Platform::String^ get() { return this->password; }
		}
	};

	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public ref class MainPage sealed
	{
	public:
		MainPage();
		property Windows::Foundation::Collections::IVector<ItemEntry^>^ ItemEntries
		{
			Windows::Foundation::Collections::IVector<ItemEntry^>^ get()
			{
				if (this->m_pwcollection == nullptr)
				{
					this->m_pwcollection = ref new Platform::Collections::Vector<ItemEntry^>();
				}
				return this->m_pwcollection;
			};
		}
	private:
		task<void> NavigatedToHandler(String^ e);
		Windows::Foundation::Collections::IVector<ItemEntry^>^ m_pwcollection;
	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;
	private:
		void lvItems_RightTapped(Platform::Object^ sender, Windows::UI::Xaml::Input::RightTappedRoutedEventArgs^ e);
		void lvItems_Holding(Platform::Object^ sender, Windows::UI::Xaml::Input::HoldingRoutedEventArgs^ e);
		void btnCopyUsername_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void btnCopyPassword_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
	};
}
