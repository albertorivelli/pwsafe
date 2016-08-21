//
// PasskeyEntryPage.xaml.cpp
// Implementation of the PasskeyEntryPage class
//

#include "pch.h"
#include "App.xaml.h"
#include "PasskeyEntryPage.xaml.h"
#include "MainPage.xaml.h"

using namespace pwsafe;

using namespace concurrency;
using namespace Platform;
using namespace Windows::Storage;
using namespace Windows::Storage::Pickers;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Interop;
using namespace Windows::UI::Xaml::Navigation;

PasskeyEntryPage::PasskeyEntryPage()
{
	InitializeComponent();
}

void PasskeyEntryPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	
}

void pwsafe::PasskeyEntryPage::btnNew_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	create_task(ApplicationData::Current->LocalFolder->CreateFileAsync(ref new String(L"test.psafe3"), CreationCollisionOption::ReplaceExisting))
		.then([this](task<StorageFile^> task)
	{
		try
		{
			StorageFile^ file = task.get();
		}
		catch (Exception^ e)
		{
			// I/O errors are reported as exceptions.
		}
	});
}


void pwsafe::PasskeyEntryPage::btnOpenFile_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	// Clear previous returned file name, if it exists, between iterations of this scenario
	txtDBPath->Text = "";

	FileOpenPicker^ openPicker = ref new FileOpenPicker();
	openPicker->ViewMode = PickerViewMode::Thumbnail;
	openPicker->SuggestedStartLocation = PickerLocationId::PicturesLibrary;
	openPicker->FileTypeFilter->Append(".psafe");
	openPicker->FileTypeFilter->Append(".psafe3");

	create_task(openPicker->PickSingleFileAsync()).then([this](StorageFile^ file)
	{
		if (file)
		{
			m_filespec = file->Path->Data();
			m_core.SetCurFile(m_filespec);
			txtDBPath->Text = file->Path;
		}
		else
		{
			txtDBPath->Text = "";
		}
	});
}

void pwsafe::PasskeyEntryPage::btnOk_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	String ^ s = ref new String(L"\\test.psafe3");
	String ^ s2 = String::Concat(ApplicationData::Current->LocalFolder->Path, s);
	m_filespec = s2->Data();
	
	m_passkey.clear();
	m_passkey.append(txtPassphrase->Password->Data());

	/*if (m_filespec->IsEmpty()) {
		m_status = TAR_OPEN_NODB;
		CPWDialog::OnCancel();
		return;
	}

	if (m_passkey.IsEmpty()) {
		gmb.AfxMessageBox(IDS_CANNOTBEBLANK);
		m_pctlPasskey->SetFocus();
		return;
	}

	if (!pws_os::FileExists(m_filespec->GetString())) {
		gmb.AfxMessageBox(IDS_FILEPATHNOTFOUND);
		if (m_MRU_combo.IsWindowVisible())
			m_MRU_combo.SetFocus();
		return;
	}*/

	ProcessPhrase();

	auto rootFrame = dynamic_cast<Windows::UI::Xaml::Controls::Frame ^>(Window::Current->Content);

	if (rootFrame != nullptr)
	{
		rootFrame->Navigate(TypeName(MainPage::typeid), nullptr);
	}
}

int PasskeyEntryPage::CheckPasskey(const StringX &filename, const StringX &passkey, PWScore *pcore)
{
	// To ensure values in current core are not overwritten when checking the passkey
	if (pcore == NULL) return m_core.CheckPasskey(filename, passkey);
	else return pcore->CheckPasskey(filename, passkey);
}

void PasskeyEntryPage::ProcessPhrase()
{
	switch (CheckPasskey(m_filespec, m_passkey))
	{
	case PWScore::SUCCESS:
		// OnOK clears the passkey, so we save it
		//	const StringX save_passkey = m_passkey;
		// Try to change read-only state if user changed checkbox:
		// r/w -> r-o always succeeds
		// r-o -> r/w may fail
		// Note that if file is read-only, m_bForceReadOnly is true -> checkbox
		// is disabled -> don't need to worry about that.
		//	if ((m_index == GCP_RESTORE || m_index == GCP_WITHEXIT) &&
		//		(m_PKE_ReadOnly == TRUE) == pws_os::IsLockedFile(LPCWSTR(m_filespec))) {
		//		GetMainDlg()->ChangeMode(false); // false means
		//										 //                           "don't prompt use for password", as we just got it.
		//	}
		//	CPWDialog::OnOK();
		//	m_passkey = save_passkey;
		break;
	case PWScore::WRONG_PASSWORD:
		//	if (m_tries++ >= 2) { // too many tries
		//		CString cs_toomany;
		//		cs_toomany.Format(IDS_TOOMANYTRIES, m_tries);
		//		gmb.AfxMessageBox(cs_toomany);
		//	}
		//	else { // try again
		//		gmb.AfxMessageBox(m_index == GCP_CHANGEMODE ? IDS_BADPASSKEY : IDS_INCORRECTKEY);
		//	}
		//	m_pctlPasskey->SetSel(MAKEWORD(-1, 0));
		//	m_pctlPasskey->SetFocus();
		break;
	case PWScore::READ_FAIL:
		//	gmb.AfxMessageBox(IDSC_FILE_UNREADABLE);
		//	CPWDialog::OnCancel();
		break;
	case PWScore::TRUNCATED_FILE:
		//	gmb.AfxMessageBox(IDSC_FILE_TRUNCATED);
		//	CPWDialog::OnCancel();
		break;
	default:
		//	//ASSERT(0);
		//	gmb.AfxMessageBox(IDSC_UNKNOWN_ERROR);
		//	CPWDialog::OnCancel();
		break;
	}
}

