import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"
import image from "../../../images/gatsby-astronaut.png"

import BlogItem from ".."

storiesOf("BlogItem", module)
    .addDecorator(jsxDecorator)
    .add("BlogItem", () => 
    <BlogItem 
    date="5.6.2018"
    title="Pienyrittäjälle kohtuuttomat maksuajat"
    number="1"
    image={image}
    link='/'
    text="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
    />)
    