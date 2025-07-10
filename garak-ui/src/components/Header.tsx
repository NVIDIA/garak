import Logo from "../logo.svg?react";

const Header = () => (
  <header className="flex items-center justify-between px-6 py-4 bg-gray-100 border-b border-gray-300">
    <div className="flex items-center gap-2 text-3xl font-semibold text-gray-800">
      <Logo height={28} data-testid="logo" />
      <span className="tracking-tight">garak</span>
    </div>
  </header>
);

export default Header;
