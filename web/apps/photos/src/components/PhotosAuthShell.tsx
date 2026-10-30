import { AuthPageShell } from "ente-accounts/components/auth/AuthPageShell";
import type { AuthPresentationConfig } from "ente-accounts/components/auth/styles";
import { isDesktop } from "ente-base/app";
import { t } from "i18next";
import type React from "react";

interface PhotosAuthShellProps extends React.PropsWithChildren {
    contentWidth?: 400 | 420;
}

const photosAuthTheme: AuthPresentationConfig = {
    primary: "#08c225",
    primaryHover: "#069d1e",
    primaryActive: "#057c18",
    focus: "#08c225",
    focusDark: "#08c225",
    link: "#08c225",
    linkDark: "#08c225",
    termsLink: "#08c225",
    termsLinkDark: "#08c225",
    passwordMessage: "#000",
    passwordMessageDark: "#fff",
    textDisabledDark: "#4d4d4d",
    wideGamutPrimary: "color(display-p3 0.03137 0.76078 0.1451)",
    mobileBrandHeight: 196,
    illustrationHeights: { desktop: 219, tablet: 172, mobile: 127, wide: 249 },
};

export function PhotosAuthShell({
    children,
    contentWidth,
}: PhotosAuthShellProps): React.JSX.Element {
    return (
        <AuthPageShell
            brand={{
                headline: t("homebase_auth_headline"),
                subtitle: t("homebase_auth_subtitle"),
                bullets: [
                    t("homebase_auth_your_storage"),
                    t("homebase_auth_encrypted"),
                    t("homebase_auth_one_sign_in"),
                ],
            }}
            presentationConfig={photosAuthTheme}
            contentWidth={contentWidth}
            viewportHeight={
                isDesktop
                    ? "calc(100svh - env(titlebar-area-height, 30px))"
                    : undefined
            }
        >
            {children}
        </AuthPageShell>
    );
}
