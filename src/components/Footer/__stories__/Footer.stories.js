import React from "react"
import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"
import imageFile from "../assets/gatsby-astronaut.png";

import Footer from ".."
storiesOf("Footer", module)
  .addDecorator(jsxDecorator)
  .add("Footer", () => <Footer  />)

  
