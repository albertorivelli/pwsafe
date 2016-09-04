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
		Platform::String^ group;
		Platform::String^ title;
		Platform::String^ user;
	public:
		ItemEntry(Platform::String^ group, Platform::String^ title, Platform::String^ user) :
			group{ group },
			title{ title },
			user{ user } {}

		property Platform::String^ Group
		{
			Platform::String^ get() { return this->group; }
		}
		property Platform::String^ Title
		{
			Platform::String^ get() { return this->title; }
		}
		property Platform::String^ User
		{
			Platform::String^ get() { return this->user; }
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
	};
}
