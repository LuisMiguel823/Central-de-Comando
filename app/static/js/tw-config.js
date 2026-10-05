/* Configuração única do Tailwind (CDN) — carregada logo depois do script do
 * Tailwind em todas as páginas (base.html e status.html), pra identidade
 * visual ficar num lugar só.
 *
 *  brand  = verde "acesso liberado" (cor de destaque)
 *  slate  = cinzas com um fio de verde (substitui os cinzas azulados padrão,
 *           então todo text-slate-* / border-slate-* já sai na nova identidade)
 */
tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        brand: {
          50: "#eefcf5",
          100: "#d5f8e6",
          200: "#aaf0ce",
          300: "#6fe3ae",
          400: "#2fcf8c",
          500: "#10b27a",
          600: "#078a5a",
          700: "#066b48",
          800: "#07553a",
          900: "#08452f",
        },
        slate: {
          50: "#f6f8f7",
          100: "#edf1ef",
          200: "#dfe6e2",
          300: "#c6d0cb",
          400: "#8f9d96",
          500: "#64736c",
          600: "#4a5852",
          700: "#35413c",
          800: "#212b26",
          900: "#121a16",
        },
      },
    },
  },
};
