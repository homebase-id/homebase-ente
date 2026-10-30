import { PhotosAuthShell } from "@/components/PhotosAuthShell";
import { styled } from "@mui/material";
import { Button } from "ente-accounts/components/auth/Button";
import { Message } from "ente-accounts/components/auth/Message";
import { ScreenHeader } from "ente-accounts/components/auth/ScreenHeader";
import { ActivityIndicator } from "ente-base/components/mui/ActivityIndicator";
import log from "ente-base/log";
import {
    ensureEntePassword,
    getProfile,
    type HomebaseDrive,
    type HomebaseProfile,
    openSavedHomebaseDrive,
    passwordFingerprint,
    signOutOfHomebase,
    YouAuthError,
} from "ente-homebase";
import { t } from "i18next";
import { useRouter } from "next/router";
import React, { useCallback, useEffect, useRef, useState } from "react";
import {
    homebaseErrorMessage,
    homebaseFailureLabel,
    homebaseStore,
    logInToEnte,
} from "../../services/homebase";

interface SignedIn {
    profile: HomebaseProfile;
    passwordCreated: boolean;
    fingerprint: string;
}

/**
 * Signed in with Homebase: the identity, and the hidden Ente password on its
 * drive (made by the first sign-in, found by every later one). The password
 * itself is never kept or shown, only a fingerprint of it.
 */
const Page: React.FC = () => {
    const router = useRouter();
    const [signedIn, setSignedIn] = useState<SignedIn | undefined>(undefined);
    const [error, setError] = useState<
        { message: string; signInAgain: boolean } | undefined
    >(undefined);
    const [continuing, setContinuing] = useState(false);
    // Kept in memory only, until Continue unlocks Ente's keys with it.
    const opened = useRef<{ drive: HomebaseDrive; password: string }>(
        undefined,
    );

    useEffect(() => {
        // Mutated by the cleanup, so a late result isn't shown after unmount.
        const effect = { cancelled: false };
        void (async () => {
            try {
                const drive = await openSavedHomebaseDrive(homebaseStore());
                if (!drive) {
                    await router.replace("/");
                    return;
                }
                const { password, created } = await ensureEntePassword(drive);
                opened.current = { drive, password };
                const fingerprint = await passwordFingerprint(password);
                const profile = await getProfile(drive.session.identity);
                if (!effect.cancelled) {
                    setSignedIn({
                        profile,
                        passwordCreated: created,
                        fingerprint,
                    });
                }
            } catch (e) {
                log.error(`Homebase: ${homebaseFailureLabel(e)}`);
                if (!effect.cancelled) {
                    setError({
                        message: homebaseErrorMessage(e),
                        signInAgain:
                            e instanceof YouAuthError &&
                            (e.kind == "unauthorized" || e.kind == "revoked"),
                    });
                }
            }
        })();
        return () => {
            effect.cancelled = true;
        };
    }, [router]);

    const continueToEnte = useCallback(async () => {
        if (!opened.current) return;
        setContinuing(true);
        try {
            await logInToEnte(opened.current.drive, opened.current.password);
            opened.current = undefined;
            await router.push("/gallery");
        } catch (e) {
            log.error(
                `Homebase: Ente login failed: ${homebaseFailureLabel(e)}`,
            );
            setError({
                message: t("homebase_ente_login_failed"),
                signInAgain: false,
            });
        }
    }, [router]);

    const signOut = useCallback(async () => {
        await signOutOfHomebase(homebaseStore());
        await router.replace("/");
    }, [router]);

    if (error) {
        return (
            <PhotosAuthShell>
                <ScreenHeader title={t("homebase_sign_in")} />
                <Message kind="error">{error.message}</Message>
                {error.signInAgain ? (
                    <Button fullWidth onClick={() => void signOut()}>
                        {t("homebase_sign_in")}
                    </Button>
                ) : (
                    <Button fullWidth onClick={() => window.location.reload()}>
                        {t("homebase_try_again")}
                    </Button>
                )}
            </PhotosAuthShell>
        );
    }

    if (!signedIn) {
        return (
            <PhotosAuthShell>
                <ActivityIndicator />
            </PhotosAuthShell>
        );
    }

    const { profile, passwordCreated, fingerprint } = signedIn;
    return (
        <PhotosAuthShell>
            <ScreenHeader
                title={t("homebase_signed_in")}
                subtitle={profile.identity}
            />
            <Identity>
                <Avatar src={profile.imageURL} alt="" />
                <div>
                    {profile.name && <Name>{profile.name}</Name>}
                    <Faint>{profile.identity}</Faint>
                </div>
            </Identity>
            <Message kind={passwordCreated ? "success" : "info"}>
                {passwordCreated
                    ? t("homebase_password_created")
                    : t("homebase_password_found")}
            </Message>
            <Explanation>
                <h2>{t("homebase_explain_what_title")}</h2>
                <p>{t("homebase_explain_what")}</p>
                <h2>{t("homebase_explain_why_title")}</h2>
                <p>{t("homebase_explain_why")}</p>
                <h2>{t("homebase_explain_secure_title")}</h2>
                <p>{t("homebase_explain_secure")}</p>
            </Explanation>
            <Fingerprint>
                {t("homebase_password_fingerprint", { fingerprint })}
            </Fingerprint>
            <Button
                fullWidth
                loading={continuing}
                onClick={() => void continueToEnte()}
            >
                {t("homebase_continue")}
            </Button>
            <Gap />
            <Button
                fullWidth
                variant="secondary"
                onClick={() => void signOut()}
            >
                {t("homebase_sign_out")}
            </Button>
        </PhotosAuthShell>
    );
};

export default Page;

const Identity = styled("div")({
    display: "flex",
    alignItems: "center",
    gap: "12px",
    margin: "16px 0",
});

const Avatar = styled("img")({
    width: "48px",
    height: "48px",
    borderRadius: "50%",
    objectFit: "cover",
    background: "var(--auth-ui-field)",
});

const Name = styled("div")({ fontWeight: 600 });

const Faint = styled("div")({
    fontSize: "14px",
    color: "var(--auth-ui-text-muted)",
});

const Fingerprint = styled(Faint)({
    fontFamily: "monospace",
    margin: "12px 0",
});

const Explanation = styled("div")({
    marginTop: "16px",
    fontSize: "14px",
    lineHeight: "20px",
    color: "var(--auth-ui-text-muted)",
    "& h2": {
        margin: "12px 0 4px",
        fontSize: "14px",
        fontWeight: 600,
        color: "var(--auth-ui-text)",
    },
    "& p": { margin: 0 },
});

const Gap = styled("div")({ height: "12px" });
