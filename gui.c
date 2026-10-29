/* =========================================================================
 * Bridge Agent window (Win32 + GDI, no external deps).
 *
 * Voice-style presence: a living 3D orb (orb_core.h) reacts to the link
 * state, network traffic, warnings and errors. Under it: live tiles and the
 * activity feed. Same gui.h API as before; the network core is untouched.
 * Falls back to headless when no desktop is available (service / session 0).
 * ========================================================================= */
#include "gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "orb_core.h"

#define TIMER_ID     1
#define FRAME_MS     33
#define FEED_CAP     400
#define FEED_MSG_MAX 240

/* palette (0xRRGGBB) */
#define C_BG_TOP  0x05070F
#define C_BG_BOT  0x0D0B1F
#define C_TEXT    0xECF0FF
#define C_MUTED   0x8A94B6
#define C_FAINT   0x5C6484
#define C_CYAN    0x00E5FF
#define C_VIOLET  0x8C64FF
#define C_MAGENTA 0xFF4FD8
#define C_OK      0x69F0AE
#define C_WARN    0xFFB74D
#define C_ERR     0xFF5252

#define RGBX(h) RGB(((h) >> 16) & 255, ((h) >> 8) & 255, (h) & 255)

typedef struct { int level; char time[12]; char msg[FEED_MSG_MAX]; } feed_t;

static HWND g_wnd = NULL;
static HANDLE g_ready_ev = NULL, g_gui_thread = NULL;
static volatile LONG g_gui_ok = 0;
static HFONT g_f_title=NULL, g_f_ui=NULL, g_f_small=NULL, g_f_mono=NULL, g_f_state=NULL;
static uint64_t g_last_seq = 0;

static orb_t g_orb;
static bw_snapshot_t g_snap;
static feed_t g_feed[FEED_CAP];
static int g_feed_head = 0, g_feed_count = 0;
static uint64_t g_prev_bytes = 0, g_prev_rpc = 0;
static int g_prev_state = -2;
static double g_act = 0.0;            /* smoothed traffic indicator */
static int g_rpc_hold = 0;            /* frames to keep the SPEAK mood after an RPC */

/* back buffer for the orb panel (top-down 32-bit DIB) */
static HBITMAP g_dib = NULL;
static uint32_t *g_dibpx = NULL;
static int g_dibw = 0, g_dibh = 0;

/* ---- small helpers ------------------------------------------------------ */
static const char *level_tag(int l){ switch(l){case 0:return "DEBUG";case 2:return "WARN";case 3:return "ERROR";}return "INFO"; }
static int level_color(int l){ switch(l){case 0:return C_FAINT;case 2:return C_WARN;case 3:return C_ERR;}return C_MUTED; }

/* Strip ANSI CSI sequences ("ESC[...m") the core embeds in log lines. */
static size_t strip_ansi(const char *in, char *out, size_t cap){
    size_t o=0;
    for(size_t i=0; in[i] && o+1<cap; ){
        if((unsigned char)in[i]==0x1B && in[i+1]=='['){ i+=2; while(in[i] && in[i]!='m') i++; if(in[i]=='m') i++; }
        else out[o++]=in[i++];
    }
    out[o]='\0'; return o;
}
static void fmt_bytes(uint64_t n, char *o, size_t c){
    const char *u="B"; double v=(double)n;
    if(v>=1024){v/=1024;u="KB";} if(v>=1024){v/=1024;u="MB";} if(v>=1024){v/=1024;u="GB";}
    snprintf(o,c,"%.1f %s",v,u);
}
static void fmt_dur(uint64_t s, char *o, size_t c){
    if(s<90) snprintf(o,c,"%llus",(unsigned long long)s);
    else if(s<5400) snprintf(o,c,"%llum %02llus",(unsigned long long)(s/60),(unsigned long long)(s%60));
    else snprintf(o,c,"%lluh %02llum",(unsigned long long)(s/3600),(unsigned long long)((s/60)%60));
}

/* map the connection state to the orb state + a short word + an accent */
static int orb_state_for(int st, int err){
    if(err) return ORB_ERROR;
    if(st==BW_STATE_CONNECTED) return ORB_IDLE;
    if(st==BW_STATE_CONNECTING) return ORB_THINK;
    return ORB_OFFLINE;
}
static const char *state_word(int st, int err){
    if(err) return "ATTENTION";
    if(st==BW_STATE_CONNECTED) return "LINKED";
    if(st==BW_STATE_CONNECTING) return "CONNECTING";
    return "OFFLINE";
}
static int state_accent(int st, int err){
    if(err) return C_ERR;
    if(st==BW_STATE_CONNECTED) return C_CYAN;
    if(st==BW_STATE_CONNECTING) return C_VIOLET;
    return C_MUTED;
}

static void feed_push(int level, uint64_t uptime_ms, const char *msg){
    feed_t *e=&g_feed[g_feed_head];
    e->level=level;
    snprintf(e->time,sizeof(e->time),"+%llus",(unsigned long long)(uptime_ms/1000));
    strip_ansi(msg,e->msg,sizeof(e->msg));
    g_feed_head=(g_feed_head+1)%FEED_CAP;
    if(g_feed_count<FEED_CAP) g_feed_count++;
}
static void feed_drain_cb(uint64_t seq,int level,uint64_t ms,const char*msg,void*ctx){
    (void)seq;(void)ctx; feed_push(level,ms,msg);
}

/* ---- GDI text helper ---------------------------------------------------- */
static void draw_text(HDC dc, HFONT f, int color, int x, int y, int w, int h, UINT flags, const char *s){
    HGDIOBJ of=SelectObject(dc,f);
    SetTextColor(dc,RGBX(color)); SetBkMode(dc,TRANSPARENT);
    RECT r={x,y,x+w,y+h};
    /* UI strings are UTF-8 (\xE2\x80\xA6 \xE2\x86\x91 \xE2\x86\x93 \xE2\x80\x94 \xC2\xB7);
     * the A-API would render them as mojibake, so convert and draw wide. */
    WCHAR ws[512];
    if(MultiByteToWideChar(CP_UTF8,0,s,-1,ws,512)>0) DrawTextW(dc,ws,-1,&r,flags);
    else DrawTextA(dc,s,-1,&r,flags);
    SelectObject(dc,of);
}

/* ---- orb back buffer ---------------------------------------------------- */
static void ensure_dib(HDC dc,int w,int h){
    if(g_dib && g_dibw==w && g_dibh==h) return;
    if(g_dib){ DeleteObject(g_dib); g_dib=NULL; g_dibpx=NULL; }
    if(w<=0||h<=0) return;
    BITMAPINFO bi; ZeroMemory(&bi,sizeof(bi));
    bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth=w; bi.bmiHeader.biHeight=-h;   /* top-down */
    bi.bmiHeader.biPlanes=1; bi.bmiHeader.biBitCount=32; bi.bmiHeader.biCompression=BI_RGB;
    g_dib=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,(void**)&g_dibpx,NULL,0);
    g_dibw=w; g_dibh=h;
}

/* Fill the orb panel: vertical gradient background + the rendered orb. */
static void paint_orb(HDC dc,int px,int py,int w,int h){
    ensure_dib(dc,w,h);
    if(!g_dibpx) return;
    for(int y=0;y<h;y++){
        float f=(float)y/(h>1?h-1:1);
        int r=(int)(((C_BG_TOP>>16&255))+((int)(C_BG_BOT>>16&255)-(int)(C_BG_TOP>>16&255))*f);
        int g=(int)(((C_BG_TOP>>8 &255))+((int)(C_BG_BOT>>8 &255)-(int)(C_BG_TOP>>8 &255))*f);
        int b=(int)(((C_BG_TOP    &255))+((int)(C_BG_BOT    &255)-(int)(C_BG_TOP    &255))*f);
        uint32_t c=(uint32_t)(r<<16|g<<8|b);
        uint32_t *row=&g_dibpx[y*w];
        for(int x=0;x<w;x++) row[x]=c;
    }
    orb_surface s={g_dibpx,w,w,h};
    float R=(float)(w<h?w:h)*0.30f;
    float dot=R/90.0f*2.1f; if(dot<1.2f) dot=1.2f;
    orb_render(&g_orb,&s,w*0.5f,h*0.52f,R,dot);
    BITMAPINFO bi; ZeroMemory(&bi,sizeof(bi));
    bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth=w; bi.bmiHeader.biHeight=-h;
    bi.bmiHeader.biPlanes=1; bi.bmiHeader.biBitCount=32; bi.bmiHeader.biCompression=BI_RGB;
    SetDIBitsToDevice(dc,px,py,w,h,0,0,0,h,g_dibpx,&bi,DIB_RGB_COLORS);
}

/* pill, tile and section primitives (flat, rounded, additive-free GDI) */
static void fill_round(HDC dc,int x,int y,int w,int h,int rad,int fill,int stroke){
    HBRUSH br=CreateSolidBrush(RGBX(fill));
    HPEN pen=CreatePen(PS_SOLID,1,RGBX(stroke<0?fill:stroke));
    HGDIOBJ ob=SelectObject(dc,br),op=SelectObject(dc,pen);
    RoundRect(dc,x,y,x+w,y+h,rad,rad);
    SelectObject(dc,ob); SelectObject(dc,op); DeleteObject(br); DeleteObject(pen);
}

/* control ids for the two buttons + the command edit */
#define IDC_RECONN 115
#define IDC_QUIT   116

/* ---- full-window paint -------------------------------------------------- */
static int g_orbH=320, g_pad=18;

static void paint(HWND w, HDC dc){
    RECT rc; GetClientRect(w,&rc);
    int W=rc.right, H=rc.bottom, pad=g_pad;
    int err = g_snap.last_error[0] ? 1 : 0;
    int accent = state_accent(g_snap.state, err);

    /* background below the orb panel */
    RECT below={0,g_orbH,W,H}; HBRUSH bb=CreateSolidBrush(RGBX(C_BG_BOT)); FillRect(dc,&below,bb); DeleteObject(bb);

    /* orb panel (its own gradient + the orb) */
    paint_orb(dc,0,0,W,g_orbH);

    /* header over the orb panel */
    draw_text(dc,g_f_small,C_CYAN,pad+2,14,300,18,DT_LEFT,"BRIDGE AGENT");
    char sub[128];
    snprintf(sub,sizeof(sub),"%s  \xC2\xB7  %s (%s)", g_snap.agent_id[0]?g_snap.agent_id:"agent", g_snap.version, g_snap.arch);
    draw_text(dc,g_f_ui,C_TEXT,pad+2,30,W-220,24,DT_LEFT,sub);

    /* connection chip, top-right */
    const char *word=state_word(g_snap.state,err);
    int cw=132,ch=30,cx=W-pad-cw,cy=16;
    fill_round(dc,cx,cy,cw,ch,ch, (accent & 0x1f1f1f), accent);
    /* status dot drawn, not a glyph: U+25CF is missing from Tahoma (XP era) */
    int dotR=5, dotX=cx+18, dotY=cy+ch/2;
    HBRUSH dot=CreateSolidBrush(RGBX(accent)); HPEN nop=CreatePen(PS_NULL,0,0);
    HGDIOBJ odb=SelectObject(dc,dot), odp=SelectObject(dc,nop);
    Ellipse(dc,dotX-dotR,dotY-dotR,dotX+dotR,dotY+dotR);
    SelectObject(dc,odb); SelectObject(dc,odp); DeleteObject(dot); DeleteObject(nop);
    char chip[48]; snprintf(chip,sizeof(chip),"%s",word);
    draw_text(dc,g_f_small,accent,cx+30,cy,cw-30,ch,DT_LEFT|DT_VCENTER|DT_SINGLELINE,chip);

    /* state label + caption under the orb (inside the panel) */
    draw_text(dc,g_f_state,accent,0,g_orbH-72,W,20,DT_CENTER,word);
    char cap[320];
    if(err) snprintf(cap,sizeof(cap),"%s",g_snap.last_error);
    else if(g_snap.state==BW_STATE_CONNECTED) snprintf(cap,sizeof(cap),"Linked to %s",g_snap.master);
    else if(g_snap.state==BW_STATE_CONNECTING) snprintf(cap,sizeof(cap),"Reaching %s\xE2\x80\xA6",g_snap.master);
    else snprintf(cap,sizeof(cap),"Waiting for the master at %s",g_snap.master);
    draw_text(dc,g_f_ui,C_MUTED,pad,g_orbH-48,W-2*pad,36,DT_CENTER|DT_WORDBREAK,cap);

    /* ---- live tiles (2 x 3) ---- */
    char rx[32],tx[32],up[32],se[32];
    fmt_bytes(g_snap.bytes_rx,rx,sizeof(rx)); fmt_bytes(g_snap.bytes_tx,tx,sizeof(tx));
    fmt_dur(g_snap.uptime_s,up,sizeof(up)); fmt_dur(g_snap.session_uptime_s,se,sizeof(se));
    const char *tl[6], *tv_[6]; char v0[48],v1[48],v2[48],v3[64],v4[64],v5[48];
    snprintf(v0,sizeof(v0),"%s",up);
    snprintf(v1,sizeof(v1),"%s",g_snap.state==BW_STATE_CONNECTED?se:"\xE2\x80\x94");
    snprintf(v2,sizeof(v2),"%llu",(unsigned long long)g_snap.rpc_total);
    snprintf(v3,sizeof(v3),"\xE2\x86\x93 %s  \xE2\x86\x91 %s",rx,tx);
    snprintf(v4,sizeof(v4),"%.0f%%  \xC2\xB7  %llu MB free",g_snap.cpu_pct,(unsigned long long)g_snap.ram_avail_mb);
    snprintf(v5,sizeof(v5),"%llu",(unsigned long long)g_snap.reconnects);
    tl[0]="UPTIME"; tl[1]="SESSION"; tl[2]="RPC CALLS"; tl[3]="NETWORK"; tl[4]="THIS PC"; tl[5]="RECONNECTS";
    tv_[0]=v0; tv_[1]=v1; tv_[2]=v2; tv_[3]=v3; tv_[4]=v4; tv_[5]=v5;
    int ty=g_orbH+pad, gap=10, tw=(W-2*pad-2*gap)/3, th=58;
    for(int i=0;i<6;i++){
        int x=pad+(i%3)*(tw+gap), y=ty+(i/3)*(th+gap);
        fill_round(dc,x,y,tw,th,14,0x10131F,0x1E2336);
        draw_text(dc,g_f_small,C_FAINT,x+12,y+9,tw-20,14,DT_LEFT,tl[i]);
        int vc = i==2?C_CYAN : i==0?C_OK : C_TEXT;
        draw_text(dc,g_f_ui,vc,x+12,y+26,tw-20,24,DT_LEFT,tv_[i]);
    }
    int feedTop = ty + 2*(th+gap) + 6;

    /* ---- activity feed ---- */
    draw_text(dc,g_f_small,C_MUTED,pad,feedTop,200,16,DT_LEFT,"ACTIVITY");
    int row=feedTop+24, rh=22, btnBar=46;
    int maxRows=(H-btnBar-row)/rh; if(maxRows<0) maxRows=0;
    for(int i=0;i<g_feed_count && i<maxRows;i++){
        int idx=(g_feed_head-1-i+FEED_CAP*2)%FEED_CAP;
        feed_t *e=&g_feed[idx];
        int y=row+i*rh;
        draw_text(dc,g_f_mono,C_FAINT,pad,y,70,rh,DT_LEFT,e->time);
        char tag[8]; snprintf(tag,sizeof(tag),"%s",level_tag(e->level));
        draw_text(dc,g_f_mono,level_color(e->level),pad+74,y,52,rh,DT_LEFT,tag);
        draw_text(dc,g_f_ui,i==0?C_TEXT:C_MUTED,pad+130,y,W-2*pad-130,rh,DT_LEFT|DT_END_ELLIPSIS,e->msg);
    }

    /* error line above the buttons */
    if(err) draw_text(dc,g_f_ui,C_ERR,pad,H-btnBar-20,W-2*pad-230,18,DT_LEFT|DT_END_ELLIPSIS,g_snap.last_error);
}

/* ---- layout + window proc ---------------------------------------------- */
static void layout(HWND w){
    RECT rc; GetClientRect(w,&rc);
    int W=rc.right,H=rc.bottom,pad=g_pad;
    g_orbH = (int)(H*0.42); if(g_orbH<220) g_orbH=220; if(g_orbH>360) g_orbH=360;
    int by=H-40, bw=110, bh=30;
    SetWindowPos(GetDlgItem(w,IDC_QUIT),NULL,W-pad-bw,by,bw,bh,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(w,IDC_RECONN),NULL,W-pad-2*bw-8,by,bw,bh,SWP_NOZORDER);
}

static void tick(HWND w){
    int prev=g_prev_state;
    bw_snapshot(&g_snap);
    bw_drain_logs(&g_last_seq,feed_drain_cb,NULL);
    int err=g_snap.last_error[0]?1:0;

    /* drive the orb: traffic -> listen/speak bursts, state -> base mood */
    uint64_t traf=g_snap.bytes_rx+g_snap.bytes_tx;
    if(g_prev_bytes && traf>g_prev_bytes){ double d=(double)(traf-g_prev_bytes); g_act=g_act*0.6+ (d>4096?1.0:d/4096.0)*0.4; }
    else g_act*=0.7;
    g_prev_bytes=traf;
    if(g_snap.rpc_total>g_prev_rpc){ orb_set_state(&g_orb,ORB_SPEAK); orb_pulse(&g_orb); g_rpc_hold=12; }
    g_prev_rpc=g_snap.rpc_total;

    int base=orb_state_for(g_snap.state,err);
    if(g_rpc_hold>0){ g_rpc_hold--; if(g_snap.state==BW_STATE_CONNECTED) base=ORB_SPEAK; }
    else if(g_snap.state==BW_STATE_CONNECTED && g_act>0.15) base=ORB_LISTEN;
    orb_set_state(&g_orb,base);
    if(g_act>0.02) orb_level(&g_orb,(float)g_act);

    if(prev!=g_snap.state){ orb_pulse(&g_orb); g_prev_state=g_snap.state; }

    orb_step(&g_orb,FRAME_MS/1000.0f);
    InvalidateRect(w,NULL,FALSE);
}

static LRESULT CALLBACK wnd_proc(HWND w, UINT m, WPARAM wp, LPARAM lp){
    switch(m){
    case WM_CREATE:{
        g_f_title=CreateFontA(24,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        g_f_ui   =CreateFontA(18,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        g_f_small=CreateFontA(13,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        g_f_state=CreateFontA(15,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,"Segoe UI");
        g_f_mono =CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FIXED_PITCH,"Consolas");
        CreateWindowExA(0,"BUTTON","Reconnect",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,w,(HMENU)(INT_PTR)IDC_RECONN,NULL,NULL);
        CreateWindowExA(0,"BUTTON","Quit agent",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,w,(HMENU)(INT_PTR)IDC_QUIT,NULL,NULL);
        SendMessageA(GetDlgItem(w,IDC_RECONN),WM_SETFONT,(WPARAM)g_f_ui,0);
        SendMessageA(GetDlgItem(w,IDC_QUIT),WM_SETFONT,(WPARAM)g_f_ui,0);
        bw_snapshot(&g_snap);
        SetTimer(w,TIMER_ID,FRAME_MS,NULL);
        return 0;
    }
    case WM_SIZE: layout(w); return 0;
    case WM_GETMINMAXINFO:{ MINMAXINFO*mmi=(MINMAXINFO*)lp; mmi->ptMinTrackSize.x=620; mmi->ptMinTrackSize.y=560; return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_TIMER: if(wp==TIMER_ID) tick(w); return 0;
    case WM_PAINT:{
        PAINTSTRUCT ps; HDC dc=BeginPaint(w,&ps);
        RECT rc; GetClientRect(w,&rc);
        HDC mem=CreateCompatibleDC(dc);
        HBITMAP bmp=CreateCompatibleBitmap(dc,rc.right,rc.bottom);
        HGDIOBJ ob=SelectObject(mem,bmp);
        paint(w,mem);
        BitBlt(dc,0,0,rc.right,rc.bottom,mem,0,0,SRCCOPY);
        SelectObject(mem,ob); DeleteObject(bmp); DeleteDC(mem);
        EndPaint(w,&ps);
        return 0;
    }
    case WM_CTLCOLORBTN: return (LRESULT)GetStockObject(NULL_BRUSH);
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if(id==IDC_RECONN) bw_force_reconnect();
        else if(id==IDC_QUIT) PostMessageA(w,WM_CLOSE,0,0);
        return 0;
    }
    case WM_CLOSE:{
        int r=MessageBoxA(w,"Stop the agent and disconnect from the master?","Bridge Agent",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2);
        if(r==IDYES){ KillTimer(w,TIMER_ID); bw_quit(); DestroyWindow(w); }
        return 0;
    }
    case WM_DESTROY:
        if(g_dib) DeleteObject(g_dib);
        DeleteObject(g_f_title); DeleteObject(g_f_ui); DeleteObject(g_f_small);
        DeleteObject(g_f_state); DeleteObject(g_f_mono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(w,m,wp,lp);
}

/* ---- thread + lifecycle ------------------------------------------------- */
static DWORD WINAPI gui_thread(LPVOID arg){
    (void)arg;
    orb_init(&g_orb);
    WNDCLASSA wc; ZeroMemory(&wc,sizeof(wc));
    wc.lpfnWndProc=wnd_proc;
    wc.hInstance=GetModuleHandleA(NULL);
    wc.hCursor=LoadCursorA(NULL,IDC_ARROW);
    wc.hbrBackground=NULL;
    wc.lpszClassName="BridgeAgentGUI";
    if(!RegisterClassA(&wc)){ InterlockedExchange(&g_gui_ok,0); SetEvent(g_ready_ev); return 1; }
    g_wnd=CreateWindowExA(0,"BridgeAgentGUI","Bridge Agent",
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,CW_USEDEFAULT,CW_USEDEFAULT,760,680,
        NULL,NULL,GetModuleHandleA(NULL),NULL);
    if(!g_wnd){ InterlockedExchange(&g_gui_ok,0); SetEvent(g_ready_ev); return 1; }
    ShowWindow(g_wnd,SW_SHOW); UpdateWindow(g_wnd);
    InterlockedExchange(&g_gui_ok,1); SetEvent(g_ready_ev);
    MSG msg;
    while(GetMessageA(&msg,NULL,0,0)>0){ TranslateMessage(&msg); DispatchMessageA(&msg); }
    g_wnd=NULL;
    return 0;
}

bool gui_start(void){
    if(g_gui_thread) return true;
    g_ready_ev=CreateEventA(NULL,TRUE,FALSE,NULL);
    if(!g_ready_ev) return false;
    g_gui_thread=CreateThread(NULL,0,gui_thread,NULL,0,NULL);
    if(!g_gui_thread){ CloseHandle(g_ready_ev); g_ready_ev=NULL; return false; }
    WaitForSingleObject(g_ready_ev,10000);
    CloseHandle(g_ready_ev); g_ready_ev=NULL;
    if(!InterlockedCompareExchange(&g_gui_ok,1,1)){ CloseHandle(g_gui_thread); g_gui_thread=NULL; return false; }
    return true;
}

void gui_stop(void){
    if(g_wnd) PostMessageA(g_wnd,WM_DESTROY,0,0);
    if(g_gui_thread){ WaitForSingleObject(g_gui_thread,3000); CloseHandle(g_gui_thread); g_gui_thread=NULL; }
}
