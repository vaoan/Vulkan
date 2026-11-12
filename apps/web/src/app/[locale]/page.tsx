const TITLES: Record<string, string> = { es: "Vulkan, el punto de partida", en: "Vulkan, the starting point" };

/** The home page: the starter's title in the route's locale. */
export default async function HomePage({ params }: { readonly params: Promise<{ locale: string }> }): Promise<React.JSX.Element> {
  const { locale } = await params;
  return (
    <main>
      <h1>{TITLES[locale]}</h1>
    </main>
  );
}
