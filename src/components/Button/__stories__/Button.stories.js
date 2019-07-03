import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Button from ".."
storiesOf("Button", module)
    .addDecorator(jsxDecorator)
    .add("Hero primary", () => 
    <Button 
    label="Tilaa uutiskirje →"
    size="lg"
    variant="heroPrimary"
    onClick={() => {}}
    />)
    .add("Hero secondary", () => 
    <Button 
    label="Lähetä →"
    size='md'
    variant="heroSecondary"
    onClick={() => {}}
    />)
    .add("Message", () => 
    <Button 
    label="Lähetä"
    size="sm"
    variant="message"
    onClick={() => {}}
    />)
    .add("Blog", () => 
    <Button 
    label="Lue lisää"
    size="sm"
    variant="blog"
    onClick={() => {}}
    />)

