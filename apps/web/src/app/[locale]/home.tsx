import { useTranslations } from "next-intl";

import { APP_NAME } from "../../shared/config/app-name";

/** The home content: the app's title in the active locale. */
export function Home(): React.JSX.Element {
  const t = useTranslations("home");
  return (
    <main>
      <h1>{t("title", { appName: APP_NAME })}</h1>
    </main>
  );
}
