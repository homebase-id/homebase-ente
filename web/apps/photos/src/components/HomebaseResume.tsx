import { PhotosAuthShell } from "@/components/PhotosAuthShell";
import { ActivityIndicator } from "ente-base/components/mui/ActivityIndicator";
import { useRouter } from "next/router";
import React, { useEffect, useState } from "react";
import { homebaseResumeRoute } from "../services/homebase";

// One of Ente's own login pages, unless this browser is signed in with
// Homebase: then it goes to /homebase, which unlocks with the hidden password.
// Ente's page isn't mounted until that's known, so its own redirects (to
// /verify, then /credentials) don't run first.
export const withHomebaseResume = (Page: React.ComponentType) => {
    const Resumable: React.FC = () => {
        const router = useRouter();
        const [showEntePage, setShowEntePage] = useState(false);

        useEffect(() => {
            const effect = { cancelled: false };
            void homebaseResumeRoute().then((route) => {
                if (effect.cancelled) return;
                if (route) void router.replace(route);
                else setShowEntePage(true);
            });
            return () => {
                effect.cancelled = true;
            };
        }, [router]);

        if (showEntePage) return <Page />;
        return (
            <PhotosAuthShell>
                <ActivityIndicator />
            </PhotosAuthShell>
        );
    };
    return Resumable;
};
