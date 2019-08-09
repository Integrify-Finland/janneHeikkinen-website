import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"
import image from "../../../images/JANNE_HEIKKINEN_260619_77.jpg"


import BlogPost from ".."

const styles = {
    display: "flex",
    justifyContent: "center",
    alignItems: "flex-start",
    backgroundColor: "#EDF5F8",
    paddingTop: "20px",
}



storiesOf("BlogPost", module)
    .addDecorator(jsxDecorator)
    .add("BlogPost", () => (
        <div style={styles}>
            <BlogPost 
            date="5.6.2018" 
            title="Pienyrittäjälle kohtuuttomat maksuajat kuriin"
            image={image}
            children={
            <div>
                <p>Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. <br></br><br></br> Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot.<br></br><br></br>
                Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin juoksupoikiin, sillä heidän täytyy luopua työnsä hedelmistä joka kuun lopuksi verottajan edessä – toisin kuin Hakaniemen keitaassa.<br></br><br></br>
                Onneksi pienyrittäjyydelle on olemassa aina vaihtoehtoja, jos SAK:n pääekonomisti Ilkka Kaukorantaa on uskominen. Hän osasi päivystävänä Twitter-viisaana laskea meille, että ”jos yrittäjyys tuottaa vähemmän kuin palkkatyö, niin kannattaa harkita palkkatyöhön siirtymistä.” <br></br><br></br>
                Ihmettelen vain, miksi emme kaikki ole aikaisemmin keksineet hakea kunnan virastoihin töihin.<br></br><br></br>
                Helpoksi ei ole pienyrittäjien arkea tehty myöskään nykymarkkinoilla, joita suuret toimijat epäterveellä tavalla määräävät.<br></br><br></br>
                Lukuisat pienyrittäjät ovat tahtomattaan törmänneet tilanteeseen, jossa isompi toimija on ilmoittanut yksipuolisesti maksuaikojen pidentämisestä. Nykyisin ei ole tavatonta, että rahat liikkuvat jopa 60 tai 90 päivän jälkeen siitä, kun suorite on siirtynyt sen tilaajalle.<br></br><br></br></p>
                <p><b>Categories:</b> politics, forest, nature</p><br></br>
                <p><b>Tags:</b> taxes, laws, society</p><br></br><br></br>
            </div>}
            />
        </div>
    ))
    