#include <windows.h>

#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/timeb.h>
#include <time.h>

#include "pegwitw.h"
#include "keyring.h"
#include "rc.h"


int InitECC(void);


LONG CALLBACK mainDlgProcWnd(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK mainDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
void GrayAll(HWND hwndDlg, BOOL on);
BOOL CALLBACK selpkDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK enterDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
LONG CALLBACK MyEditProc(HWND hEdit, UINT message, WPARAM wParam, LPARAM lParam);
void MesgBox(const char *m1, const char *m2);
void Thread1(VOID *proc, HWND hwndDlg);
void GenPub(HWND hwndDlg);
void Sig(HWND hwndDlg);
void Enc(HWND hwndDlg);
void Dec(HWND hwndDlg);
void Ver(HWND hwndDlg);
void SigClp(HWND hwndDlg);
void EncClp(HWND hwndDlg);
void DecClp(HWND hwndDlg);
void VerClp(HWND hwndDlg);
void SigFile(HWND hwndDlg);
void EncFile(HWND hwndDlg);
void DecFile(HWND hwndDlg);
void VerFile(HWND hwndDlg);
void Set_Key(HWND hwndDlg, int num);
void Sel_Key(HWND hwndDlg);
int Add_Key(HWND hwndDlg);
int Del_Key(HWND hwndDlg);
char * BrowseFile(HWND hWnd, int sig);
void SetRandom(long val1);
int CheckError(HWND hwndDlg, int err);
FILE * chkopen( char * s, char * mode, HWND hwndDlg );


HINSTANCE hInst;
HWND hDlgMain;

WNDPROC lpEditProc;

char szEXEname[MAX_PATH] = "\0";

DWORD dwTime = 0;

#define RNDMSZ 256
char cRandom[RNDMSZ+4];
int npRandom = 0;

#define PWCHAR '='

char *szAppName = "PEGWIT";
char *AboutText = "PegwitW v1.00 alfa.04 for Windows (http://disastry.dhs.org/pegwit/), 2000";


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS    WndClass;
    MSG         msg;
    char *cerr;

    cerr = checkEndian();
    if (cerr) {
        MessageBox(NULL, cerr, szAppName, MB_OK);
        return 1;
    }
    if (InitECC()) {
        MessageBox(NULL, "InitECC() failed", szAppName, MB_OK);
        return 1;
    }

    hInst = hInstance;

    WndClass.style          =  CS_SAVEBITS | CS_DBLCLKS | CS_BYTEALIGNWINDOW;
    WndClass.lpfnWndProc    =  (WNDPROC)mainDlgProcWnd;
    WndClass.cbClsExtra     =  0;
    WndClass.cbWndExtra     =  DLGWINDOWEXTRA;
    WndClass.hInstance      =  hInst;
    WndClass.hIcon          =  LoadIcon(hInst, szAppName);
    WndClass.hCursor        =  LoadCursor(NULL, IDC_ARROW);
    WndClass.hbrBackground  =  (HBRUSH)(COLOR_WINDOW + 1);
    WndClass.lpszMenuName   =  NULL;
    WndClass.lpszClassName  =  szAppName;
    if (!RegisterClass(&WndClass)) {
        MessageBox(NULL, "RegisterClass error", szAppName, MB_OK);
        return 0;
    }
    memset(cRandom, ' ', RNDMSZ);
    strcpy(cRandom+RNDMSZ, "\r\n");
    SetRandom((long)hInst + (long)hPrevInstance);
    LoadKeyring();
    GetModuleFileName(hInst, szEXEname, sizeof(szEXEname));
    hDlgMain = CreateDialog(hInst, szAppName, NULL, mainDlgProc);
    if (hDlgMain)
        while (GetMessage(&msg, NULL, 0, 0))
            if (!IsDialogMessage(hDlgMain, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
    FreeKeyring();
    prng_init(0);
    burn_stack();
    return 0;
} // WinMain


LONG CALLBACK MyEditProc(HWND hEdit, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    /*case WM_GETTEXT:
        if (InSendMessage()) {
            *(char *)wParam = 0;
            return 0;
        }
        break;*/
    case WM_PASTE:
    case WM_CUT:
    case WM_COPY:
        return 0;
    default:
        break;
    }
    return CallWindowProc(lpEditProc, hEdit, message, wParam, lParam);
} // MyEditProc


LONG CALLBACK mainDlgProcWnd(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    SetRandom((long)hDlg + message + wParam + lParam);
    switch (message) {
    case WM_NCHITTEST: {
        LONG lRetVal = DefDlgProc(hDlg, message, wParam, lParam);
        if (lRetVal == HTCLIENT)
            return HTCAPTION;
        //if (lRetVal == HTRIGHT)
        //    return HTBORDER;
        //if (lRetVal == HTLEFT)
        //    return HTBORDER;
        if (lRetVal == HTTOP)
            return HTBORDER;
        if (lRetVal == HTBOTTOM)
            return HTBORDER;
        if (lRetVal == HTBOTTOMRIGHT)
            return HTRIGHT; //HTBOTTOM;
        if (lRetVal == HTBOTTOMLEFT)
            return HTLEFT; //HTBOTTOM;
        if (lRetVal == HTTOPRIGHT)
            return HTRIGHT; //HTTOP;
        if (lRetVal == HTTOPLEFT)
            return HTLEFT; //HTTOP;
        return lRetVal;
        }
    }
    return DefDlgProc(hDlg, message, wParam, lParam);
} // mainDlgProcWnd


//HFONT hFontr, hFontn;
BOOL CALLBACK mainDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    RECT     rect;
    POINT    pt;
    static   int nPrevHeight, nPrevWidth, nPrevLBHeight, nPrevLBWidth, minWidth, minHeight;

    switch (uMsg) {
    case WM_INITDIALOG:
        CheckRadioButton(hwndDlg, IDC_WIN, IDC_FILE, IDC_CLIPB);
        Set_Key(hwndDlg, 0);
        dwTime = GetTickCount();
        SetTimer(hwndDlg, 1, 1000, NULL);         
        AppendMenu(GetSystemMenu(hwndDlg, FALSE), MF_SEPARATOR, 0, NULL);
        AppendMenu(GetSystemMenu(hwndDlg, FALSE), MF_STRING, ID_ABOUT, "About");
        DragAcceptFiles(hwndDlg, TRUE);
        lpEditProc = (WNDPROC)GetWindowLong(GetDlgItem(hwndDlg, IDC_SECRET), GWL_WNDPROC);
        SetWindowLong(GetDlgItem(hwndDlg, IDC_SECRET), GWL_WNDPROC, (LPARAM)MyEditProc);
        //hFont = LoadResource(NULL, FindResource(NULL, 1, RT_FONT));
        //AddFontResource(szEXEname);
        //hFontr = CreateFont(8, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        //    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH|FF_DONTCARE, "randomz");
        //hFontn = (HFONT)SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETFONT, 0, TRUE);
        //SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_SETFONT, (WPARAM)hFontr, TRUE);
        SendDlgItemMessage(hwndDlg, IDC_SECRET, EM_SETPASSWORDCHAR, PWCHAR, 0);
        SendDlgItemMessage(hwndDlg, IDC_KEYNUM, EM_LIMITTEXT, 3, 0);
        SetDlgItemText(hwndDlg, IDC_KEYNUM, "1");
        //        EM_SETHANDLE
        //
        GetWindowRect( hwndDlg, &rect );
        minWidth = rect.right-rect.left;
        minHeight = (rect.bottom-rect.top);
        GetClientRect( hwndDlg, &rect );
        nPrevHeight = rect.bottom-rect.top;
        nPrevWidth = rect.right-rect.left;
        GetWindowRect( GetDlgItem(hwndDlg, IDC_TEXT), &rect );
        nPrevLBHeight = rect.bottom-rect.top;
        nPrevLBWidth = rect.right-rect.left;
        return TRUE;
    case WM_DROPFILES:               //file was dropped over window
        {
        char *szFileName;
        int nFNsize;
        HANDLE hFilesInfo = (HANDLE)wParam;
        // get number of files dropped
        int wTotalFiles = DragQueryFile(hFilesInfo, -1, NULL, 0);
        // add the file names to the listbox
        if (wTotalFiles) {
            // get the first file name size
            nFNsize = DragQueryFile(hFilesInfo, 0, NULL, 0);
            if (nFNsize) {
                szFileName = malloc(nFNsize+1);
                if (szFileName) {
                    // get the first file name
                    DragQueryFile(hFilesInfo, 0, (LPSTR)szFileName, nFNsize+1);
                    SetDlgItemText(hwndDlg, IDC_FILENAME, szFileName);
                    free(szFileName);
                    SendMessage(hwndDlg, WM_COMMAND, IDC_FILE, 0);
                }
            }
        }
        // release memory Windows allocated for transferring 
        // filenames to app
        DragFinish(hFilesInfo);
        }
        return TRUE;
    case WM_SYSCOMMAND:
        switch (LOWORD(wParam)) {
        case SC_CLOSE:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        case ID_ABOUT:
            SendMessage(hwndDlg, WM_COMMAND, ID_ABOUT, 0);
            return TRUE;
        }
        return FALSE;
    case WM_COMMAND:
        dwTime = GetTickCount();
        switch (LOWORD(wParam)) {
        case ID_ABOUT:
            MessageBox(hwndDlg, AboutText, "Pegwit for MS Windows", MB_OK);
            return TRUE;
        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        case IDC_CONV: {
            BOOL noconv = !IsDlgButtonChecked(hwndDlg, IDC_CONV);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SIG), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_VER), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_MAKEPK), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SAVEPK), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SELPK), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_DELPK), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PKDATA), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PKNAME), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDT_PK), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDT_KEYNUM), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_KEYNUM), noconv);
            EnableWindow(GetDlgItem(hwndDlg, IDC_TOSELF), noconv);
            SetDlgItemText(hwndDlg, IDT_SECRET, noconv ? "Private Key" : "Key");
            SetDlgItemText(hwndDlg, IDC_SECRET, "");
            }
            return TRUE;
        case IDC_MAKEPK:
            Thread1(GenPub,hwndDlg);
            return TRUE;
        case IDC_SIG:
            if (IsDlgButtonChecked(hwndDlg, IDC_WIN))
                Thread1(Sig,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_CLIPB))
                Thread1(SigClp,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_FILE))
                Thread1(SigFile,hwndDlg);
            return TRUE;
        case IDC_VER:
            if (IsDlgButtonChecked(hwndDlg, IDC_WIN))
                Thread1(Ver,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_CLIPB))
                Thread1(VerClp,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_FILE))
                Thread1(VerFile,hwndDlg);
            return TRUE;
        case IDC_ENC:
            if (IsDlgButtonChecked(hwndDlg, IDC_WIN))
                Thread1(Enc,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_CLIPB))
                Thread1(EncClp,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_FILE))
                Thread1(EncFile,hwndDlg);
            return TRUE;
        case IDC_DEC:
            if (IsDlgButtonChecked(hwndDlg, IDC_WIN))
                Thread1(Dec,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_CLIPB))
                Thread1(DecClp,hwndDlg);
            else if (IsDlgButtonChecked(hwndDlg, IDC_FILE))
                Thread1(DecFile,hwndDlg);
            return TRUE;
        case IDC_WIN:
        case IDC_CLIPB:
        case IDC_FILE:
            EnableWindow(GetDlgItem(hwndDlg, IDC_BIN), LOWORD(wParam) == IDC_FILE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_FILENAME), LOWORD(wParam) == IDC_FILE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_BROWSE), LOWORD(wParam) == IDC_FILE);
            CheckRadioButton(hwndDlg, IDC_WIN, IDC_FILE, LOWORD(wParam));
            return TRUE;
        case IDC_BROWSE: {
            char * t_fn = BrowseFile(hwndDlg, 0);
            if (t_fn) {
                SetDlgItemText(hwndDlg, IDC_FILENAME, t_fn);
                free(t_fn);
            }
            }
            return TRUE;
        case IDC_SAVEPK:
            if (Add_Key(hwndDlg))
                SaveKeyring();
            return TRUE;
        case IDC_SELPK:
            Sel_Key(hwndDlg);
            return TRUE;
        case IDC_DELPK:
            if (Del_Key(hwndDlg))
                SaveKeyring();
            return TRUE;
        case IDC_SHOWPW:
            //SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_SETFONT, (WPARAM)(IsDlgButtonChecked(hwndDlg, IDC_SHOWPW) ? hFontn : hFontr), TRUE);
            SendDlgItemMessage(hwndDlg, IDC_SECRET, EM_SETPASSWORDCHAR, (WPARAM)(IsDlgButtonChecked(hwndDlg, IDC_SHOWPW) ? 0 : PWCHAR), 0);
            InvalidateRect(GetDlgItem(hwndDlg, IDC_SECRET), 0, TRUE);
            return TRUE;
        }
        return FALSE;
    case WM_TIMER:
        if (GetTickCount() - dwTime > 300000) {
            dwTime = GetTickCount();
            SetDlgItemText(hwndDlg, IDC_SECRET, "");
        }
        return TRUE;
    case WM_CLOSE:
        //DeleteObject(hFontr);
        //RemoveFontResource(szEXEname);
        KillTimer(hwndDlg, 1);
        //return EndDialog(hwndDlg, 0);
        return DestroyWindow(hwndDlg);
    case WM_DESTROY:
        PostQuitMessage(0);
        return TRUE;
    case  WM_SIZE:
        if (wParam==SIZE_RESTORED) {
            int nHeight,nWidth;

            nHeight = HIWORD(lParam); // height of client area
            nWidth = LOWORD(lParam); // width of client area

            GetWindowRect( GetDlgItem(hwndDlg, IDC_TEXT), &rect );
            pt.x = rect.left;
            pt.y = rect.top;
            ScreenToClient( hwndDlg, &pt );

            nPrevLBHeight += nHeight-nPrevHeight;
            nPrevLBWidth += nWidth-nPrevWidth;
            nPrevHeight = nHeight;
            nPrevWidth = nWidth;
            MoveWindow( GetDlgItem(hwndDlg, IDC_TEXT),     //BOOL MoveWindow(hwnd, nLeft, nTop, nWidth, nHeight, fRepaint)
                     pt.x,
                     pt.y,
                     nPrevLBWidth, //rect.right-rect.left,
                     nPrevLBHeight,
                     TRUE );
        }
        return FALSE;
    case  WM_GETMINMAXINFO: {
        MINMAXINFO FAR* lpmmi;

        lpmmi = (MINMAXINFO FAR*) lParam;
        lpmmi->ptMinTrackSize.x = minWidth;
        //lpmmi->ptMaxTrackSize.x = maxWidth;
        lpmmi->ptMinTrackSize.y = minHeight;
        }
        return TRUE;
    }
    return FALSE;
} // mainDlgProc


void GrayAll(HWND hwndDlg, BOOL on)
{
    BOOL noconv;
    WORD wParam;
    if (on) {
        SetWindowText(hwndDlg, "PEGWIT - Wait");
        EnableWindow(GetDlgItem(hwndDlg, IDC_TEXT), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SHOWPW), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDT_SECRET), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SECRET), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CONV), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_WIN), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CLIPB), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILE), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_ENC), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_DEC), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SIG), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_VER), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_MAKEPK), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SAVEPK), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SELPK), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_DELPK), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_PKDATA), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_PKNAME), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDT_PK), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDT_KEYNUM), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_KEYNUM), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_TOSELF), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BIN), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILENAME), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BROWSE), FALSE);
    } else {
        SetWindowText(hwndDlg, "PEGWIT");
        EnableWindow(GetDlgItem(hwndDlg, IDC_TEXT), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SHOWPW), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDT_SECRET), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SECRET), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CONV), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_WIN), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CLIPB), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILE), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_ENC), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_DEC), TRUE);
        noconv = !IsDlgButtonChecked(hwndDlg, IDC_CONV);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SIG), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_VER), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_MAKEPK), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SAVEPK), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SELPK), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_DELPK), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_PKDATA), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_PKNAME), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDT_PK), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDT_KEYNUM), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_KEYNUM), noconv);
        EnableWindow(GetDlgItem(hwndDlg, IDC_TOSELF), noconv);
        wParam = 0;
        if (IsDlgButtonChecked(hwndDlg, IDC_WIN))
            wParam = IDC_WIN;
        else if (IsDlgButtonChecked(hwndDlg, IDC_CLIPB))
            wParam = IDC_CLIPB;
        else if (IsDlgButtonChecked(hwndDlg, IDC_FILE))
            wParam = IDC_FILE;
        EnableWindow(GetDlgItem(hwndDlg, IDC_BIN), wParam == IDC_FILE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILENAME), wParam == IDC_FILE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BROWSE), wParam == IDC_FILE);
    }
}


BOOL CALLBACK selpkDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int ii, lbidx;
    HDC hDC;
    SIZE extsize;
    long lLongest;
    RECT     rect;
    POINT    pt;
    static   int nPrevHeight, nPrevWidth, nPrevLBHeight, nPrevLBWidth, minWidth, minHeight;

    SetRandom((long)hwndDlg + uMsg + wParam + lParam);
    switch (uMsg) {
    case WM_INITDIALOG:
        if (GetNumKeys()) {
            hDC = GetDC(GetDlgItem(hwndDlg, IDC_PKLIST));
            lLongest = 0;
            for (ii=0; ii<GetNumKeys(); ii++)
                if (GetKeyPtr(ii)) {
                    if (GetTextExtentPoint32(hDC, GetKeyPtr(ii), strlen(GetKeyPtr(ii)), &extsize))
                        if (extsize.cx > lLongest)
                            lLongest = extsize.cx;
                    lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_ADDSTRING, 0, (LPARAM)GetKeyPtr(ii));
                    if (lbidx >= 0)
                        SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_SETITEMDATA, lbidx, ii);
                }
            if (lLongest);
                SendMessage(GetDlgItem(hwndDlg, IDC_PKLIST), LB_SETHORIZONTALEXTENT, lLongest, 0);
        }
        GetWindowRect( hwndDlg, &rect );
        minWidth = rect.right-rect.left;
        minHeight = (rect.bottom-rect.top)/2;
        GetClientRect( hwndDlg, &rect );
        nPrevHeight = rect.bottom-rect.top;
        nPrevWidth = rect.right-rect.left;
        GetWindowRect( GetDlgItem(hwndDlg, IDC_PKLIST), &rect );
        nPrevLBHeight = rect.bottom-rect.top;
        nPrevLBWidth = rect.right-rect.left;
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDCANCEL:
            return EndDialog(hwndDlg, 0);
        case IDC_PKLIST:
            if (HIWORD(wParam) != LBN_DBLCLK)
                break;
        case IDOK:
            lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETCURSEL, 0, 0);
            if (lbidx >= 0)
                lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETITEMDATA, lbidx, 0);
            if (lbidx < 0)
                lbidx = -1;
            return EndDialog(hwndDlg, lbidx+1);
        case IDC_DELPK:
            lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETCURSEL, 0, 0);
            if (lbidx >= 0)
                lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETITEMDATA, lbidx, 0);
            if (lbidx >= 0) {
                if (SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_DELETESTRING, lbidx, 0) >= 0) {
                    DelKey(lbidx);
                    SaveKeyring();
                }
            }
            return TRUE;
        case IDC_SETDEF:
            lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETCURSEL, 0, 0);
            if (lbidx >= 0)
                lbidx = SendDlgItemMessage(hwndDlg, IDC_PKLIST, LB_GETITEMDATA, lbidx, 0);
            if (lbidx >= 0) {
                SetDefKey(lbidx);
                SaveKeyring();
            }
            return TRUE;
        }
        return FALSE;
    case WM_CLOSE:
        return EndDialog(hwndDlg, 0);
    case  WM_SIZE:
        if (wParam==SIZE_RESTORED) {
            int nHeight,nWidth;

            nHeight = HIWORD(lParam); // height of client area
            nWidth = LOWORD(lParam); // width of client area

            GetWindowRect( GetDlgItem(hwndDlg, IDC_PKLIST), &rect );
            pt.x = rect.left;
            pt.y = rect.top;
            ScreenToClient( hwndDlg, &pt );

            nPrevLBHeight += nHeight-nPrevHeight;
            nPrevLBWidth += nWidth-nPrevWidth;
            nPrevHeight = nHeight;
            nPrevWidth = nWidth;
            MoveWindow( GetDlgItem(hwndDlg, IDC_PKLIST),     //BOOL MoveWindow(hwnd, nLeft, nTop, nWidth, nHeight, fRepaint)
                     pt.x,
                     pt.y,
                     nPrevLBWidth, //rect.right-rect.left,
                     nPrevLBHeight,
                     TRUE );
        }
        return FALSE;
    case  WM_GETMINMAXINFO: {
        MINMAXINFO FAR* lpmmi;

        lpmmi = (MINMAXINFO FAR*) lParam;
        lpmmi->ptMinTrackSize.x = minWidth;
        //lpmmi->ptMaxTrackSize.x = maxWidth;
        lpmmi->ptMinTrackSize.y = minHeight;
        }
        return TRUE;
    }
    return FALSE;
} // selpkDlgProc


BOOL CALLBACK enterDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static int size = 0;
    static char *buf;

    switch (uMsg) {
    case WM_INITDIALOG:
        size = *(int *)lParam;
        buf = (char *)lParam;
        SendMessage(hwndDlg, WM_SETTEXT, 0, (LPARAM)((char *)lParam)+10);
        SetDlgItemText(hwndDlg, IDC_TEXT, ((char *)lParam)+10);
        EnableWindow(GetDlgItem(hwndDlg, IDOK), FALSE);
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDCANCEL:
            return EndDialog(hwndDlg, 0);
        case IDOK:
            return EndDialog(hwndDlg, GetDlgItemText(hwndDlg, IDC_TEXT, buf, size));
        case IDC_TEXT:
            EnableWindow(GetDlgItem(hwndDlg, IDOK), (SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_GETTEXTLENGTH, 0, 0) > 30));
            return TRUE;
        }
        return FALSE;
    case WM_CLOSE:
        return EndDialog(hwndDlg, 0);
    }
    return FALSE;
} // enterDlgProc


void MesgBox(const char *m1, const char *m2)
{
    MessageBox(hDlgMain, m1, m2?m2:szAppName, MB_OK);
}


void Sel_Key(HWND hwndDlg)
{
    int num;

    num = DialogBox(hInst, "SELECTPK", hwndDlg, selpkDlgProc) -1;
    if (num < 0)
        return;
    Set_Key(hwndDlg, num);
} // Sel_Key

void Set_Key(HWND hwndDlg, int num)
{
    char pkdata[KEYSIZE+1];

    if (num>=GetNumKeys())
        return;
    if (!GetKeyPtr(num))
        return;
    SetDlgItemText(hwndDlg, IDC_PKNAME, GetKeyPtr(num)+KEYSIZE+1);
    strncpy(pkdata, GetKeyPtr(num), KEYSIZE);
    pkdata[KEYSIZE] = 0;
    SetDlgItemText(hwndDlg, IDC_PKDATA, pkdata);
} // Set_Key

int Add_Key(HWND hwndDlg)
{
    char * t_kn, * t_kd;
    int s_kn, s_kd, keynum;

    s_kn = SendDlgItemMessage(hwndDlg, IDC_PKNAME, WM_GETTEXTLENGTH, 0, 0);
    s_kd = SendDlgItemMessage(hwndDlg, IDC_PKDATA, WM_GETTEXTLENGTH, 0, 0);
    if (!s_kn || s_kd!=KEYSIZE)
        return 0;
    s_kn++;
    s_kd++;
    t_kn = malloc(s_kn+2);
    t_kd = malloc(s_kd+2);
    if (!t_kn || !t_kd) {
        if(t_kn) free(t_kn);
        if(t_kd) free(t_kd);
        return 0;
    }
    GetDlgItemText(hwndDlg, IDC_PKNAME, t_kn, s_kn);
    GetDlgItemText(hwndDlg, IDC_PKDATA, t_kd, s_kd);
    keynum = FindKey(NULL, t_kd);
    if (keynum<0)
        AddKey(t_kn, t_kd);
    free(t_kn);
    free(t_kd);
    return keynum<0 ? 1 : 0;
} // Add_Key

int Del_Key(HWND hwndDlg)
{
    char * t_kn, * t_kd;
    int s_kn, s_kd, keynum;

    s_kn = SendDlgItemMessage(hwndDlg, IDC_PKNAME, WM_GETTEXTLENGTH, 0, 0);
    s_kd = SendDlgItemMessage(hwndDlg, IDC_PKDATA, WM_GETTEXTLENGTH, 0, 0);
    if (!s_kn || s_kd!=KEYSIZE)
        return 0;
    s_kn++;
    s_kd++;
    t_kn = malloc(s_kn+2);
    t_kd = malloc(s_kd+2);
    if (!t_kn || !t_kd) {
        if(t_kn) free(t_kn);
        if(t_kd) free(t_kd);
        return 0;
    }
    GetDlgItemText(hwndDlg, IDC_PKNAME, t_kn, s_kn);
    GetDlgItemText(hwndDlg, IDC_PKDATA, t_kd, s_kd);
    keynum = FindKey(t_kn, t_kd);
    if (keynum>=0) {
        DelKey(keynum);
        SetDlgItemText(hwndDlg, IDC_PKNAME, "");
        SetDlgItemText(hwndDlg, IDC_PKDATA, "");
    }
    free(t_kn);
    free(t_kd);
    return keynum>=0 ? 1 : 0;
} // Del_Key


/*
void wipefile(FILE * f_unk)
{ // I don't know it it works - not tested
    char * t_unk;
    int s_unk, s_tmp, n_pos;

    if (!f_unk)
        return;
    fflush(f_unk);
    _setmode(_fileno(f_unk), _O_BINARY);
    fseek(f_unk, 0, SEEK_END);
    s_tmp = s_unk = ftell(f_unk);
    if (s_unk <= 0)
        return;
    if (s_tmp > 0x8000)
        s_tmp = 0x8000;
    t_unk = malloc(s_tmp+2);
    if (!t_unk)
        return;
    n_pos = 0;
    while (s_unk>0) {
        s_unk -= s_tmp;
        memset(t_unk, 0xB, s_tmp);
        fseek(f_unk, n_pos, SEEK_SET);
        fwrite(t_unk, 1, s_tmp, f_unk);
        memset(t_unk, 0xF6, s_tmp);
        fseek(f_unk, n_pos, SEEK_SET);
        fwrite(t_unk, 1, s_tmp, f_unk);
        n_pos += s_tmp;
        if (s_unk <= 0x8000)
            s_tmp = s_unk;
    }
    free(t_unk);
} // wipefile
*/


FILE * fileFromBuf(char *t_unk, int addcrlf)
{
    FILE * f_unk;
    int s_unk;

    f_unk = tmpfile();
    _setmode(_fileno(f_unk), _O_BINARY);
    s_unk = strlen(t_unk);
    if (t_unk[s_unk-1] == '\r')
        {strcat(t_unk, "\n"); s_unk++;}
    else if (addcrlf && t_unk[s_unk-1] != '\n')
        {strcat(t_unk, "\r\n"); s_unk+=2;}
    fwrite(t_unk, 1, s_unk, f_unk);
    fflush(f_unk);
    _setmode(_fileno(f_unk), _O_TEXT);
    fseek(f_unk, 0, SEEK_SET);
    return f_unk;
} // fileFromBuf


void Thread1(VOID *proc, HWND hwndDlg)
{
    DWORD ThreadId;
    HANDLE hThread;

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)proc, hwndDlg, CREATE_SUSPENDED, &ThreadId);
    if (hThread) {
        //SetThreadPriority(hThread, THREAD_PRIORITY_BELOW_NORMAL);
        SetThreadPriority(hThread, GetThreadPriority(hThread)-1);
        ResumeThread(hThread);
    }
}

void GenPub(HWND hwndDlg)
{
    char * t_key, * t_out;
    int s_key, res;

    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_key)
        return;
    s_key++;
    t_key = malloc(s_key+2);
    if (!t_key)
        return;
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    res = do_make_key(0, t_key, 0, &t_out);
    if (CheckError(hwndDlg, res)) {
        SetDlgItemText(hwndDlg, IDC_PKDATA, t_out);
        SetDlgItemText(hwndDlg, IDC_PKNAME, "My Key");
    }
    free(t_key);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // GenPub


void Sig(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, s_inp, res;

    s_inp = SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key = malloc(s_key+2);
    if (!t_inp || !t_key) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_TEXT, t_inp, s_inp);
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    res = do_sign(0, t_key, 0, 0, 0, t_inp, &t_out);
    if (CheckError(hwndDlg, res))
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
    memset(t_key,0,s_key);
    free(t_key);
    free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // Sig

void Ver(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, s_inp, res;

    s_inp = SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_PKDATA, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key = malloc(s_key+2);
    if (!t_inp || !t_key) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_TEXT, t_inp, s_inp);
    GetDlgItemText(hwndDlg, IDC_PKDATA, t_key, s_key);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    res = do_verify(0, t_key, 0, 0, 0, 0, t_inp, &t_out, 0);
    if (CheckError(hwndDlg, res)) {
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
        MessageBox(hwndDlg, "Signature good", szAppName, MB_OK);
    }
    free(t_key);
    free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // Ver

void Enc(HWND hwndDlg)
{
    char * t_key[2], * t_inp, * t_out, * t_sec;
    int s_key, s_inp, conv, keysrc, toself, res;

    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    toself = IsDlgButtonChecked(hwndDlg, IDC_TOSELF);
    keysrc = conv ? IDC_SECRET : IDC_PKDATA;
    s_inp = SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, keysrc, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key[0] = malloc(s_key+2);
    t_key[1] = NULL;
    if (!t_inp || !t_key[0]) {
        if(t_inp) free(t_inp);
        if(t_key[0]) free(t_key[0]);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_TEXT, t_inp, s_inp);
    GetDlgItemText(hwndDlg, keysrc, t_key[0], s_key);
    if (!conv && toself && GetNumKeys() && GetKeyPtr(0)) {
        t_key[1] = GetKeyPtr(0);
    } else
        toself = 0;
    if (conv) {
        t_sec = 0;
    } else {
        SetRandom(0);
        t_sec = cRandom;
    }
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    if (conv)
        res = do_encrypt_c(0, t_key[0], 0, 0, 0, t_inp, &t_out);
    else
        res = do_encrypt_pk(0, t_key, 0, 0, 0, 0, t_inp, &t_out, t_sec, toself?2:1);
    if (CheckError(hwndDlg, res))
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
    prng_set_rnd(0,0,0,0); prng_set_rnd(0,0,0,0);
    memset(t_key[0],0,s_key);
    free(t_key[0]);
    memset(t_inp,0,s_inp);
    free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // Enc

void Dec(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, s_inp, conv, res, keyn;
    char mesg[64];

    s_inp = SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    if (!(keyn = GetDlgItemInt(hwndDlg, IDC_KEYNUM, NULL, FALSE))) {
        SetDlgItemText(hwndDlg, IDC_KEYNUM, "1");
        keyn = 1;
    }
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key = malloc(s_key+2);
    if (!t_inp || !t_key) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_TEXT, t_inp, s_inp);
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    if (conv)
        res = do_decrypt_c(0, t_key, 0, 0, 0, t_inp, &t_out);
    else
        res = do_decrypt_pk(0, t_key, 0, 0, 0, t_inp, &t_out, &keyn);
    if (!conv && res == ERR_BADKEYNUM) {
        sprintf(mesg, "Encrypted only to %u keys !", keyn);
        MessageBox(hwndDlg, mesg, szAppName, MB_OK);
    } else
    if (CheckError(hwndDlg, res)) {
        if (!conv && keyn > 1) {
            sprintf(mesg, "Encrypted to %u keys !", keyn);
            MessageBox(hwndDlg, mesg, szAppName, MB_OK);
        }
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
    }
    memset(t_key,0,s_key);
    free(t_key);
    free(t_inp);
    if (t_out) {memset(t_out,0,strlen(t_out)); p_free(t_out);}
    GrayAll(hwndDlg, FALSE);
} // Dec


char * getClipboardText(HWND hWnd)
{
    char * t_inp, *t_clp;
    int s_inp;
    HANDLE hClpD;

    t_inp = 0;
    if (OpenClipboard(hWnd)) {
        if (IsClipboardFormatAvailable(CF_TEXT)) {
            if (hClpD = GetClipboardData(CF_TEXT)) {
                if (t_clp = GlobalLock(hClpD)) {
                    s_inp = strlen(t_clp);
                    t_inp = malloc(s_inp+3);
                    if (t_inp)
                        strcpy(t_inp, t_clp);
                    GlobalUnlock(hClpD);
                }
            }
        }
        CloseClipboard();
    }
    return t_inp;
} // getClipboardText

void SigClp(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, res;

    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_key)
        return;
    s_key++;
    t_inp = getClipboardText(hwndDlg);
    if (!t_inp) {
        //MessageBox(hwndDlg, "nesanaaca", szAppName, MB_OK);
        return;
    }
    t_key = malloc(s_key+2);
    if (!t_key)
        return;
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    res = do_sign(0, t_key, 0, 0, 0, t_inp, &t_out);
    if (CheckError(hwndDlg, res)) {
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, EM_SETSEL, 0, -1);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_COPY, 0, 0);
        //SetDlgItemText(hwndDlg, IDC_TEXT, "Text in clipboard signed");
        /*if (OpenClipboard(hwndDlg)) {
            EmptyClipboard();
            hClpD = GlobalAlloc(GMEM_MOVEABLE|GMEM_DDESHARE, sizeof(t_out)+1);
            if (hClpD) {
                t_clp = GlobalLock(hClpD);
                strcpy(t_clp, t_out);
                GlobalUnlock(hClpD);
                SetClipboardData(CF_TEXT, hClpD);
            }
            CloseClipboard();
        }*/
    }
    memset(t_key,0,s_key);
    free(t_key);
    free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // SigClp

void VerClp(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, res;

    s_key = SendDlgItemMessage(hwndDlg, IDC_PKDATA, WM_GETTEXTLENGTH, 0, 0);
    if (!s_key)
        return;
    s_key++;
    t_inp = getClipboardText(hwndDlg);
    if (!t_inp) {
        //MessageBox(hwndDlg, "nesanaaca", szAppName, MB_OK);
        return;
    }
    t_key = malloc(s_key+2);
    if (!t_key)
        return;
    GetDlgItemText(hwndDlg, IDC_PKDATA, t_key, s_key);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    res = do_verify(0, t_key, 0, 0, 0, 0, t_inp, &t_out, 0);
    if (CheckError(hwndDlg, res)) {
        MessageBox(hwndDlg, "Signature good", szAppName, MB_OK);
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, EM_SETSEL, 0, -1);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_COPY, 0, 0);
        //SetDlgItemText(hwndDlg, IDC_TEXT, "Text in clipboard verified");
    }
    if (t_key) free(t_key);
    if (t_inp) free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // VerClp

void EncClp(HWND hwndDlg)
{
    char * t_key[2], * t_inp, * t_out, * t_sec;
    int s_key, conv, keysrc, toself, res;

    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    toself = IsDlgButtonChecked(hwndDlg, IDC_TOSELF);
    keysrc = conv ? IDC_SECRET : IDC_PKDATA;
    s_key = SendDlgItemMessage(hwndDlg, keysrc, WM_GETTEXTLENGTH, 0, 0);
    if (!s_key)
        return;
    s_key++;
    t_inp = getClipboardText(hwndDlg);
    if (!t_inp) {
        //MessageBox(hwndDlg, "nesanaaca", szAppName, MB_OK);
        return;
    }
    t_key[0] = malloc(s_key+2);
    t_key[1] = NULL;
    if (!t_key[0]) {
        if(t_key[0]) free(t_key[0]);
        return;
    }
    GetDlgItemText(hwndDlg, keysrc, t_key[0], s_key);
    if (!conv && toself && GetNumKeys()) {
        t_key[1] = GetKeyPtr(0);
    } else
        toself = 0;
    if (conv) {
        t_sec = 0;
    } else {
        SetRandom(0);
        t_sec = cRandom;
    }
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    if (conv)
        res = do_encrypt_c(0, t_key[0], 0, 0, 0, t_inp, &t_out);
    else
        res = do_encrypt_pk(0, t_key, 0, 0, 0, 0, t_inp, &t_out, t_sec, toself?2:1);
    if (CheckError(hwndDlg, res)) {
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, EM_SETSEL, 0, -1);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_COPY, 0, 0);
        //SetDlgItemText(hwndDlg, IDC_TEXT, "Text in clipboard encrypted");
    }
    prng_set_rnd(0,0,0,0); prng_set_rnd(0,0,0,0);
    memset(t_key[0],0,s_key);
    free(t_key[0]);
    memset(t_inp,0,strlen(t_inp));
    free(t_inp);
    if (t_out) p_free(t_out);
    GrayAll(hwndDlg, FALSE);
} // EncClp

void DecClp(HWND hwndDlg)
{
    char * t_key, * t_inp, * t_out;
    int s_key, conv, keyn, res;
    char mesg[64];

    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_key)
        return;
    if (!(keyn = GetDlgItemInt(hwndDlg, IDC_KEYNUM, NULL, FALSE))) {
        SetDlgItemText(hwndDlg, IDC_KEYNUM, "1");
        keyn = 1;
    }
    s_key++;
    t_inp = getClipboardText(hwndDlg);
    if (!t_inp) {
        //MessageBox(hwndDlg, "nesanaaca", szAppName, MB_OK);
        return;
    }
    t_key = malloc(s_key+2);
    if (!t_key)
        return;
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    GrayAll(hwndDlg, TRUE);
    t_out = NULL;
    if (conv)
        res = do_decrypt_c(0, t_key, 0, 0, 0, t_inp, &t_out);
    else
        res = do_decrypt_pk(0, t_key, 0, 0, 0, t_inp, &t_out, &keyn);
    if (!conv && res == ERR_BADKEYNUM) {
        sprintf(mesg, "Encrypted only to %u keys !", keyn);
        MessageBox(hwndDlg, mesg, szAppName, MB_OK);
    } else
    if (CheckError(hwndDlg, res)) {
        if (!conv && keyn > 1) {
            sprintf(mesg, "Encrypted to %u keys !", keyn);
            MessageBox(hwndDlg, mesg, szAppName, MB_OK);
        }
        SetDlgItemText(hwndDlg, IDC_TEXT, t_out);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, EM_SETSEL, 0, -1);
        SendDlgItemMessage(hwndDlg, IDC_TEXT, WM_COPY, 0, 0);
        //SetDlgItemText(hwndDlg, IDC_TEXT, "Text in clipboard decrypted");
    }
    memset(t_key,0,s_key);
    free(t_key);
    free(t_inp);
    if (t_out) {memset(t_out,0,strlen(t_out)); p_free(t_out);}
    GrayAll(hwndDlg, FALSE);
} // DecClp


char * BrowseFile(HWND hWnd, int sig)
{
    OPENFILENAME fn;
    char * t_filename;

    t_filename = malloc(261);
    if (!t_filename)
        return NULL;
    *t_filename = 0;
    memset(&fn, 0, sizeof(fn));
    fn.lStructSize = sizeof(fn);
    fn.hwndOwner = hWnd;
    fn.hInstance = hInst;
    fn.lpstrFile = t_filename;
    fn.nMaxFile = 260;
    fn.lpstrTitle = sig ? "Select signature" : "Select file";
    fn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_LONGNAMES | OFN_NOCHANGEDIR | OFN_NONETWORKBUTTON;
    if (!GetOpenFileName(&fn)) {
        free(t_filename);
        return NULL;
    }
    return t_filename;
} // BrowseFile

void SigFile(HWND hwndDlg)
{
    FILE * f_inp, * f_out;
    char * t_key, * t_inp, * t_out;
    int s_key, s_inp, binmode, res;

    s_inp = SendDlgItemMessage(hwndDlg, IDC_FILENAME, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key = malloc(s_key+2);
    t_out = malloc(s_inp+6);
    if (!t_inp || !t_key || !t_out) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        if(t_out) free(t_out);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_FILENAME, t_inp, s_inp);
    s_inp = strlen(t_inp);
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);
    strcpy(t_out, t_inp);
    strcat(t_out, ".sig");
    binmode = IsDlgButtonChecked(hwndDlg, IDC_BIN);
    f_inp = chkopen(t_inp, binmode ? "rb" : "r", hwndDlg);
    f_out = chkopen(t_out, binmode ? "wb" : "w", hwndDlg);
    free(t_inp);
    free(t_out);
    if (!f_inp || !f_out)
        return;
    GrayAll(hwndDlg, TRUE);
    res = do_sign(0, t_key, f_inp, f_out, binmode, 0, 0);
    memset(t_key,0,s_key);
    free(t_key);
    _fcloseall();
    CheckError(hwndDlg, res);
    GrayAll(hwndDlg, FALSE);
} // SigFile

void VerFile(HWND hwndDlg)
{
    FILE * f_inp, * f_out, * f_sec;
    FILE * f_tst;
    char * t_key, * t_inp, * t_out, * t_sec;
    int s_key, s_inp, binmode, res, sig;

    s_inp = SendDlgItemMessage(hwndDlg, IDC_FILENAME, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_PKDATA, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+6);
    t_key = malloc(s_key+2);
    t_out = malloc(s_inp+6);
    t_sec = malloc(s_inp+6);
    if (!t_inp || !t_key || t_out || t_sec) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        if(t_out) free(t_out);
        if(t_sec) free(t_sec);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_FILENAME, t_inp, s_inp);
    s_inp = strlen(t_inp);
    GetDlgItemText(hwndDlg, IDC_PKDATA, t_key, s_key);

    binmode = IsDlgButtonChecked(hwndDlg, IDC_BIN);
    if (binmode) {
        strcpy(t_sec, t_inp);
        free(t_out);
        t_out = NULL;
        f_tst = NULL;
        if (s_inp > 4 && !strcmp(t_inp+s_inp-4, ".sig") && t_inp[s_inp-5] != '\\' && t_inp[s_inp-5] != ':') {
            sig = 1;
            t_inp[s_inp-4] = 0;
        } else {
            sig = 0;
            strcat(t_inp, ".sig");
        }
        f_tst = fopen(t_inp, "rb");
        if (f_tst) {
            fclose(f_tst);
        } else {
            free(t_inp);
            if (t_inp = BrowseFile(hwndDlg, !sig))
                f_tst = fopen(t_inp, "rb");
            if (f_tst)
                fclose(f_tst);
            else {
                free(t_sec);
                free(t_key);
                if (t_inp)
                    free(t_inp);
                return;
            }
        }
        if (!sig) {
            t_out = t_inp; // use t_out as tmp
            t_inp = t_sec;
            t_sec = t_out;
            t_out = NULL;
        }
    } else {
        strcpy(t_out, t_inp);
        free(t_sec);
        t_sec = NULL;
        if (s_inp > 4 && !strcmp(t_out+s_inp-4, ".sig") && t_out[s_inp-5] != '\\' && t_out[s_inp-5] != ':')
            t_out[s_inp-4] = 0;
        else
            strcat(t_out, ".uns");
    }

    f_inp = chkopen(t_inp, binmode ? "rb" : "r", hwndDlg);
    free(t_inp);
    if (t_out) {
        f_out = chkopen(t_out, binmode ? "wb" : "w", hwndDlg);
        free(t_out);
    } else
        f_out = 0;
    if (t_sec) {
        f_sec = chkopen(t_sec, binmode ? "rb" : "r", hwndDlg);
        free(t_sec);
    } else
        f_sec = 0;
    if (!f_inp || (t_out && !f_out) || (t_sec && !f_sec))
        return;
    GrayAll(hwndDlg, TRUE);
    res = do_verify(0, t_key, f_inp, f_out, f_sec, binmode, 0, 0, 0);
    free(t_key);
    _fcloseall();
    if (CheckError(hwndDlg, res))
        MessageBox(hwndDlg, "Signature good", szAppName, MB_OK);
    GrayAll(hwndDlg, FALSE);
} // VerFile

void EncFile(HWND hwndDlg)
{
    FILE * f_inp, * f_out;
    char * t_key[2], * t_inp, * t_out, * t_sec;
    int s_key, s_inp, binmode, conv, keysrc, toself, res;

    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    toself = IsDlgButtonChecked(hwndDlg, IDC_TOSELF);
    keysrc = conv ? IDC_SECRET : IDC_PKDATA;
    s_inp = SendDlgItemMessage(hwndDlg, IDC_FILENAME, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, keysrc, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key[0] = malloc(s_key+2);
    t_key[1] = NULL;
    t_out = malloc(s_inp+6);
    if (!t_inp || !t_key[0] || !t_out) {
        if(t_inp) free(t_inp);
        if(t_key[0]) free(t_key[0]);
        if(t_out) free(t_out);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_FILENAME, t_inp, s_inp);
    s_inp = strlen(t_inp);
    GetDlgItemText(hwndDlg, keysrc, t_key[0], s_key);
    if (!conv && toself && GetNumKeys()) {
        t_key[1] = GetKeyPtr(0);
    } else {
        toself = 0;
    }

    strcpy(t_out, t_inp);
    strcat(t_out, ".enc");

    if (conv) {
        t_sec = 0;
    } else {
        SetRandom(0);
        t_sec = cRandom;
    }

    binmode = IsDlgButtonChecked(hwndDlg, IDC_BIN);
    f_inp = chkopen(t_inp, binmode ? "rb" : "r", hwndDlg);
    f_out = chkopen(t_out, binmode ? "wb" : "w", hwndDlg);
    free(t_inp);
    free(t_out);
    if (!f_inp || !f_out)
        return;
    GrayAll(hwndDlg, TRUE);
    if (conv)
        res = do_encrypt_c(0, t_key[0], f_inp, f_out, binmode, 0, 0);
    else
        res = do_encrypt_pk(0, t_key, f_inp, f_out, 0, binmode, 0, 0, t_sec, toself?2:1);
    prng_set_rnd(0,0,0,0); prng_set_rnd(0,0,0,0);
    memset(t_key[0],0,s_key);
    free(t_key[0]);
    _fcloseall();
    CheckError(hwndDlg, res);
    GrayAll(hwndDlg, FALSE);
} // EncFile

void DecFile(HWND hwndDlg)
{
    FILE * f_inp, * f_out;
    char * t_key, * t_inp, * t_out;
    int s_key, s_inp, binmode, conv, keyn, res;
    char mesg[64];

    s_inp = SendDlgItemMessage(hwndDlg, IDC_FILENAME, WM_GETTEXTLENGTH, 0, 0);
    s_key = SendDlgItemMessage(hwndDlg, IDC_SECRET, WM_GETTEXTLENGTH, 0, 0);
    if (!s_inp || !s_key)
        return;
    if (!(keyn = GetDlgItemInt(hwndDlg, IDC_KEYNUM, NULL, FALSE))) {
        SetDlgItemText(hwndDlg, IDC_KEYNUM, "1");
        keyn = 1;
    }
    s_inp++;
    s_key++;
    t_inp = malloc(s_inp+2);
    t_key = malloc(s_key+2);
    t_out = malloc(s_inp+6);
    if (!t_inp || !t_key || !t_out) {
        if(t_inp) free(t_inp);
        if(t_key) free(t_key);
        if(t_out) free(t_out);
        return;
    }
    GetDlgItemText(hwndDlg, IDC_FILENAME, t_inp, s_inp);
    s_inp = strlen(t_inp);
    GetDlgItemText(hwndDlg, IDC_SECRET, t_key, s_key);

    strcpy(t_out, t_inp);
    if (s_inp > 4 && !strcmp(t_out+s_inp-4, ".enc") && t_out[s_inp-5] != '\\' && t_out[s_inp-5] != ':')
        t_out[s_inp-4] = 0;
    else
        strcat(t_out, ".dec");

    binmode = IsDlgButtonChecked(hwndDlg, IDC_BIN);
    f_inp = chkopen(t_inp, binmode ? "rb" : "r", hwndDlg);
    f_out = chkopen(t_out, binmode ? "wb" : "w", hwndDlg);
    free(t_inp);
    free(t_out);
    if (!f_inp || !f_out)
        return;
    GrayAll(hwndDlg, TRUE);
    conv = IsDlgButtonChecked(hwndDlg, IDC_CONV);
    if (conv)
        res = do_decrypt_c(0, t_key, f_inp, f_out, binmode, 0, 0);
    else
        res = do_decrypt_pk(0, t_key, f_inp, f_out, binmode, 0, 0, &keyn);
    memset(t_key,0,s_key);
    free(t_key);
    _fcloseall();
    if (!conv && res == ERR_BADKEYNUM) {
        sprintf(mesg, "Encrypted only to %u keys !", keyn);
        MessageBox(hwndDlg, mesg, szAppName, MB_OK);
    } else
    if (CheckError(hwndDlg, res)) {
        if (!conv && keyn > 1) {
            sprintf(mesg, "Encrypted to %u keys !", keyn);
            MessageBox(hwndDlg, mesg, szAppName, MB_OK);
        }
    }
    GrayAll(hwndDlg, FALSE);
} // DecFile


void SetRandom(long val1)
{
// not wery good random value collector
    char rt[40];
    int ii;
    struct _timeb timeptr;

    _ltoa(val1, rt+0, 16);
    _ltoa(clock(), rt+8, 16);
    _ltoa(GetTickCount(), rt+16, 16);
    _ftime(&timeptr);
    _ltoa(timeptr.time, rt+24, 16);
    _itoa(timeptr.millitm, rt+32, 16);

    for (ii=0; ii<37; ii++) {
        cRandom[npRandom] = rt[ii] ^ (cRandom[npRandom] << (rt[ii]&3));
        //if ((unsigned)cRandom[npRandom] < 0x20)
        //    cRandom[npRandom] += 0x20;
        if (++npRandom == RNDMSZ) {
            prng_set_rnd( 0, 0, cRandom, npRandom ); /* buffer full - hash entropy */
            npRandom = 0;
        }
    }

    if (!val1 && npRandom) {
        prng_set_rnd( 0, 0, cRandom, npRandom ); /* hash entropy */
    }

    /*{
    FILE * rf = fopen("f:\\rndtest.txt", "a");
    if (rf) {
        fputs(cRandom, rf);
        fclose(rf);
    }
    }*/
} // SetRandom


//
const char err_output [] = "Pegwit, error writing output, disk full?";
const char err_signature [] = "signature did not verify";
const char err_decrypt [] = "decryption failed";
const char err_clearsig_header_not_found [] = 
  "Clearsignature header \"###\" not found";
const char err_decode_failed[] =
"Pegwit; Out of range characters encountered in ASCII armouring";

int CheckError(HWND hwndDlg, int err)
{
  const char * errmes;
  if (err) {
      switch (err) {
      case ERR_NOERROR:
        break;
      case ERR_NOHEADER:
        errmes = err_clearsig_header_not_found;
        break;
      case ERR_OUTPUT:
        errmes = err_output;
        break;
      case ERR_SYMDECRYPT:
        errmes = err_decrypt;
        break;
      case ERR_NOMEMORY:
        errmes = "Out of memory";
        break;
      case ERR_BADSIGN:
        errmes = err_signature;
        break;
      case ERR_INPUT:
        errmes = "Input error";
        break;
      case ERR_BADSYMCIPHER:
        errmes = "Unknow cipher";
        break;
      case ERR_NOECC:
        errmes = "Bad file";
        break;
      case ERR_BADARMOR:
        errmes = err_decode_failed;
        break;
      case ERR_UNKNOWN:
      default:
        errmes = "Unknown error";
        break;
      }
      MessageBox(hwndDlg, errmes, szAppName, MB_OK);
  }
  return !err;
}

FILE * chkopen( char * s, char * mode, HWND hwndDlg )
{
    FILE * result = fopen(s,mode);
    if (!result) {
        MessageBox(NULL, "failed to open", s, MB_OK);
    }
    return result;
}
