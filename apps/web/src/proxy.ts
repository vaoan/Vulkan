import createProxy from "next-intl/middleware";

import { routing } from "./i18n/routing";

/** Next 16's `proxy` (the former middleware): puts every path under a locale. */
export default createProxy(routing);

export const config = { matcher: ["/((?!api|trpc|_next|_vercel|.*[.].*).*)"] };
