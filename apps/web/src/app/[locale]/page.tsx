import { APP_NAME } from "../../shared/config/app-name";

const TITLES: Record<string, string> = { es: `${APP_NAME}, el punto de partida`, en: `${APP_NAME}, the starting point` };

/** The home page: the app's title in the route's locale. */
export default async function HomePage({ params }: { readonly params: Promise<{ locale: string }> }): Promise<React.JSX.Element> {
  const { locale } = await params;
  return (
    <main>
      <h1>{TITLES[locale]}</h1>
    </main>
  );
}
