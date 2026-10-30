import { PhotosAuthShell } from "@/components/PhotosAuthShell";
import { Button } from "ente-accounts/components/auth/Button";
import { Message } from "ente-accounts/components/auth/Message";
import { ScreenHeader } from "ente-accounts/components/auth/ScreenHeader";
import { ActivityIndicator } from "ente-base/components/mui/ActivityIndicator";
import log from "ente-base/log";
import { finishHomebaseSignIn } from "ente-homebase";
import { t } from "i18next";
import { useRouter } from "next/router";
import React, { useEffect, useRef, useState } from "react";
import {
    homebaseErrorMessage,
    homebaseFailureLabel,
    homebaseStore,
} from "../../services/homebase";

/**
 * Where the identity sends the browser back to after YouAuth. Finishes the
 * sign-in, then goes to the signed-in page.
 */
const Page: React.FC = () => {
    const router = useRouter();
    const [error, setError] = useState<string | undefined>(undefined);
    // The pending sign-in can be used once; don't finish it twice when React
    // runs the effect twice in development.
    const started = useRef(false);

    useEffect(() => {
        if (started.current) return;
        started.current = true;
        const callback = new URLSearchParams(window.location.search);
        // The query carries the key exchange: keep it out of the history.
        window.history.replaceState(
            window.history.state,
            "",
            window.location.pathname,
        );
        void finishHomebaseSignIn(callback, sessionStorage, homebaseStore())
            .then(() => router.replace("/homebase"))
            .catch((e: unknown) => {
                log.error(
                    `Homebase sign-in failed: ${homebaseFailureLabel(e)}`,
                );
                setError(homebaseErrorMessage(e));
            });
    }, [router]);

    return (
        <PhotosAuthShell>
            {error ? (
                <>
                    <ScreenHeader title={t("homebase_sign_in")} />
                    <Message kind="error">{error}</Message>
                    <Button fullWidth onClick={() => void router.replace("/")}>
                        {t("homebase_try_again")}
                    </Button>
                </>
            ) : (
                <>
                    <ScreenHeader title={t("homebase_signing_in")} />
                    <ActivityIndicator />
                </>
            )}
        </PhotosAuthShell>
    );
};

export default Page;
