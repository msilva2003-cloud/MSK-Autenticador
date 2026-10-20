#include "camera.h"

#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <wrl/client.h>
#include <gdiplus.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace camera {
namespace {

using Microsoft::WRL::ComPtr;
constexpr wchar_t dialog_class[] = L"MSKAuthenticatorCamera";

struct Session {
    ComPtr<IMFMediaSource> source;
    ComPtr<IMFSourceReader> reader;
    std::vector<std::uint8_t> pixels;
    std::vector<auth::Account> accounts;
    UINT32 width = 0;
    UINT32 height = 0;
    bool failed = false;

    Session() {
        if (FAILED(MFStartup(MF_VERSION))) throw std::runtime_error("Camera indisponivel");
        try {
            ComPtr<IMFAttributes> attributes;
            if (FAILED(MFCreateAttributes(&attributes, 1)) ||
                FAILED(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                                           MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID)))
                throw std::runtime_error("Camera indisponivel");
            IMFActivate** devices = nullptr;
            UINT32 count = 0;
            if (FAILED(MFEnumDeviceSources(attributes.Get(), &devices, &count)) || !count)
                throw std::runtime_error("Nenhuma camera disponivel");
            const auto activated = devices[0]->ActivateObject(IID_PPV_ARGS(&source));
            for (UINT32 i = 0; i < count; ++i) devices[i]->Release();
            CoTaskMemFree(devices);
            if (FAILED(activated)) throw std::runtime_error("Nao foi possivel abrir a camera");
            ComPtr<IMFAttributes> reader_options;
            if (FAILED(MFCreateAttributes(&reader_options, 1)) ||
                FAILED(reader_options->SetUINT32(MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE)) ||
                FAILED(MFCreateSourceReaderFromMediaSource(source.Get(), reader_options.Get(), &reader)))
                throw std::runtime_error("Camera indisponivel");
            ComPtr<IMFMediaType> requested;
            if (FAILED(MFCreateMediaType(&requested)) ||
                FAILED(requested->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video)) ||
                FAILED(requested->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32)) ||
                FAILED(reader->SetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr,
                                                    requested.Get())))
                throw std::runtime_error("Formato de camera nao suportado");
            ComPtr<IMFMediaType> actual;
            if (FAILED(reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, &actual)) ||
                FAILED(MFGetAttributeSize(actual.Get(), MF_MT_FRAME_SIZE, &width, &height)) ||
                !width || !height || static_cast<std::uint64_t>(width) * height > 1920ull * 1080ull)
                throw std::runtime_error("Resolucao de camera nao suportada");
        } catch (...) {
            reader.Reset();
            source.Reset();
            MFShutdown();
            throw;
        }
    }

    ~Session() {
        if (!pixels.empty()) SecureZeroMemory(pixels.data(), pixels.size());
        reader.Reset();
        source.Reset();
        MFShutdown();
    }

    void capture() {
        DWORD stream = 0, flags = 0;
        LONGLONG timestamp = 0;
        ComPtr<IMFSample> sample;
        if (FAILED(reader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &stream, &flags,
                                      &timestamp, &sample))) {
            failed = true;
            return;
        }
        if (!sample) return;
        ComPtr<IMFMediaBuffer> buffer;
        if (FAILED(sample->ConvertToContiguousBuffer(&buffer))) return;
        BYTE* source_bytes = nullptr;
        DWORD maximum = 0, length = 0;
        if (FAILED(buffer->Lock(&source_bytes, &maximum, &length))) return;
        const auto needed = static_cast<std::size_t>(width) * height * 4;
        if (length >= needed) {
            pixels.resize(needed);
            std::memcpy(pixels.data(), source_bytes, needed);
        }
        buffer->Unlock();
    }
};

LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<Session*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_NCCREATE:
        SetWindowLongPtrW(window, GWLP_USERDATA,
            reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams));
        return TRUE;
    case WM_TIMER:
        if (state) {
            state->capture();
            if (state->failed) { DestroyWindow(window); return 0; }
            if (!state->pixels.empty()) {
                try {
                    state->accounts = auth::read_qr_pixels(state->pixels.data(),
                        static_cast<int>(state->width), static_cast<int>(state->height));
                    DestroyWindow(window);
                    return 0;
                } catch (const std::exception&) { /* Ainda nao ha QR legivel. */ }
                InvalidateRect(window, nullptr, FALSE);
            }
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(window, &ps);
        RECT area{};
        GetClientRect(window, &area);
        FillRect(dc, &area, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        if (state && !state->pixels.empty()) {
            Gdiplus::Bitmap image(static_cast<INT>(state->width), static_cast<INT>(state->height),
                                  static_cast<INT>(state->width * 4), PixelFormat32bppRGB,
                                  state->pixels.data());
            Gdiplus::Graphics graphics(dc);
            graphics.DrawImage(&image, Gdiplus::Rect(0, 0, area.right, area.bottom - 48));
        }
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        RECT caption{12, area.bottom - 44, area.right - 12, area.bottom - 6};
        DrawTextW(dc, L"Aponte a camera para o QR. Esc cancela.", -1, &caption,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        EndPaint(window, &ps);
        return 0;
    }
    case WM_KEYDOWN:
        if (wparam == VK_ESCAPE) { DestroyWindow(window); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        KillTimer(window, 1);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

std::vector<auth::Account> scan(HWND parent) {
    Session session;
    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpfnWndProc = procedure;
    klass.lpszClassName = dialog_class;
    klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&klass);
    RECT owner{};
    GetWindowRect(parent, &owner);
    const int width = 520, height = 440;
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, dialog_class, L"Ler QR pela camera",
        WS_CAPTION | WS_SYSMENU | WS_POPUP,
        owner.left + (owner.right - owner.left - width) / 2,
        owner.top + (owner.bottom - owner.top - height) / 2,
        width, height, parent, nullptr, klass.hInstance, &session);
    if (!window) throw std::runtime_error("Janela de camera indisponivel");
    EnableWindow(parent, FALSE);
    ShowWindow(window, SW_SHOW);
    SetTimer(window, 1, 250, nullptr);
    MSG event{};
    while (IsWindow(window) && GetMessageW(&event, nullptr, 0, 0) > 0) {
        TranslateMessage(&event);
        DispatchMessageW(&event);
    }
    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    if (session.failed) throw std::runtime_error("Falha ao ler a camera");
    return std::move(session.accounts);
}

} // namespace camera
