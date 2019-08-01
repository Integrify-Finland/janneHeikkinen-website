import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"
import image from "../../../images/JANNE_HEIKKINEN_260619_77.jpg"

import BlogItem from ".."

const styles = {
    display: "flex",
    justifyContent: "center",
    alignItems: "flex-start",
    height: "100vh",
    backgroundColor: "#EDF5F8",
    paddingTop: "20px"
}

const text = "Julkaistu alun perin Kalevassa 5.6.2019 Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot. Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin"
const shortText = text.substr(0, 416) + '...'

storiesOf("BlogItem", module)
    .addDecorator(jsxDecorator)
    .add("BlogItem", () => (
        <div style={styles}>
            <BlogItem 
            date="5.6.2018" 
            title="Pienyrittäjälle kohtuuttomat maksuajat"
            number="1"
            image={image}
            text={shortText}
            />
        </div>
    ))
    