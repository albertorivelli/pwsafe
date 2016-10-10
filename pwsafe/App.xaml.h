//
// App.xaml.h
// Declaration of the App class.
//

#pragma once

#include "App.g.h"
#include "core\PWScore.h"

namespace pwsafe
{
	extern PWScore m_core;

	/// <summary>
	/// Provides application-specific behavior to supplement the default Application class.
	/// </summary>
	ref class App sealed
	{
	protected:
		virtual void OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs^ e) override;

	internal:
		App();

	private:
		void OnSuspending(Platform::Object^ sender, Windows::ApplicationModel::SuspendingEventArgs^ e);
		void OnNavigationFailed(Platform::Object ^sender, Windows::UI::Xaml::Navigation::NavigationFailedEventArgs ^e);
		void App_BackRequested(Platform::Object ^sender, Windows::UI::Core::BackRequestedEventArgs ^e);
		void App_BackPressed(Platform::Object ^sender, Windows::Phone::UI::Input::BackPressedEventArgs^ e);
	};
}
