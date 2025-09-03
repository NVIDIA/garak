import { AppBar, AppBarLogo, Text } from "@kui/react";

const Header = () => (
  <AppBar 
    slotLeft={
      <>
        <AppBarLogo size="small" />
        <Text kind="label/bold/2xl">GARAK</Text>
      </>
    }
  />
)

export default Header;
