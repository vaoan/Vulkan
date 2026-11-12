import { useTranslations } from "next-intl";

import { APP_NAME } from "../config/app-name";

/** The page header: the app's name and a slot for the sign-in control. */
export function Header({ signIn }: { readonly signIn?: React.ReactNode }): React.JSX.Element {
  const t = useTranslations("header");
  return (
    <header>
      <span>{APP_NAME}</span>
      <div>{signIn ?? <button type="button">{t("signIn")}</button>}</div>
    </header>
  );
}
