import { styled } from "@mui/material";
import { Button } from "ente-accounts/components/auth/Button";
import { Form } from "ente-accounts/components/auth/Form";
import { FormFields } from "ente-accounts/components/auth/FormFields";
import { FormFooter } from "ente-accounts/components/auth/FormFooter";
import { TextField } from "ente-accounts/components/auth/TextField";
import log from "ente-base/log";
import {
    hasHomebaseSignIn,
    isValidIdentity,
    startHomebaseSignIn,
} from "ente-homebase";
import { t } from "i18next";
import { useRouter } from "next/router";
import React, { useCallback, useEffect, useState } from "react";
import {
    homebaseErrorMessage,
    homebaseFailureLabel,
    homebaseStore,
} from "../services/homebase";

/**
 * "Sign in with Homebase", below the email login: an identity field that
 * sends the browser to that identity's YouAuth page.
 */
export const HomebaseLogin: React.FC = () => {
    const router = useRouter();
    const [identity, setIdentity] = useState("");
    const [error, setError] = useState<string | undefined>(undefined);
    const [isSubmitting, setIsSubmitting] = useState(false);

    // Already signed in with Homebase: go to its signed-in page.
    useEffect(() => {
        void hasHomebaseSignIn(homebaseStore())
            .then((signedIn) => {
                if (signedIn) void router.replace("/homebase");
            })
            .catch((e: unknown) =>
                log.error(
                    `Failed to read the Homebase sign-in: ${homebaseFailureLabel(e)}`,
                ),
            );
    }, [router]);

    const handleSubmit = useCallback(
        async (event: React.SubmitEvent<HTMLFormElement>) => {
            event.preventDefault();
            if (!isValidIdentity(identity)) {
                setError(t("homebase_identity_invalid"));
                return;
            }
            setError(undefined);
            setIsSubmitting(true);
            try {
                window.location.assign(
                    await startHomebaseSignIn(
                        identity,
                        window.location.origin,
                        sessionStorage,
                        navigator.userAgent,
                    ),
                );
            } catch (e) {
                log.error(
                    `Failed to start the Homebase sign-in: ${homebaseFailureLabel(e)}`,
                );
                setError(homebaseErrorMessage(e));
                setIsSubmitting(false);
            }
        },
        [identity],
    );

    return (
        <>
            <Divider>{t("homebase_or")}</Divider>
            <Form onSubmit={(event) => void handleSubmit(event)}>
                <FormFields>
                    <TextField
                        name="homebase-identity"
                        value={identity}
                        onChange={(event) => setIdentity(event.target.value)}
                        type="text"
                        inputMode="url"
                        autoComplete="off"
                        label={t("homebase_identity_label")}
                        placeholder={t("homebase_identity_placeholder")}
                        disabled={isSubmitting}
                        error={!!error}
                        helperText={error}
                    />
                </FormFields>
                <FormFooter>
                    <Button
                        fullWidth
                        type="submit"
                        variant="secondary"
                        loading={isSubmitting}
                    >
                        {t("homebase_sign_in")}
                    </Button>
                </FormFooter>
            </Form>
        </>
    );
};

const Divider = styled("div")({
    display: "flex",
    alignItems: "center",
    gap: "12px",
    margin: "24px 0",
    fontSize: "12px",
    fontWeight: 500,
    color: "var(--auth-ui-text-faint)",
    "&::before, &::after": {
        content: '""',
        flex: 1,
        borderTop: "1px solid currentColor",
        opacity: 0.4,
    },
});
