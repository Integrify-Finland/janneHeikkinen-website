import React from "react"
import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"
import imageFile from "../assets/gatsby-astronaut.png";

import AboutTextBlock from ".."
storiesOf("AboutTextBlock", module)
  .addDecorator(jsxDecorator)
  .add("with title, text, icon, isLeft =true", () => <AboutTextBlock title="That's the title" text="This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!"  icon={imageFile} isLeft={true} />)

  .add("with title, text, icon, isLeft =false", () => <AboutTextBlock title="That's another title" text="This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!This is some random text. Enjoy!" icon={imageFile} isLeft={false} />)

  
