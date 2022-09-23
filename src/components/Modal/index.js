import React from "react"
import "./styles.scss"

const Modal = ({ setIsOpen, setIsAgreeing }) => {
  return (
    <div className="modal-wrapper">
      <div className="darkBG" onClick={() => setIsOpen(false)} />
      <div className="centered">
        <div className="modal">
          <h5 className="heading">Tietosuojaseloste</h5>
          <div className="modalContent">
            <p>
              Kuka on rekisterinpitäjä ja mihin voit olla tarvittaessa
              yhteydessä? REKISTERINPITÄJÄ: Vapaa Pohjoinen ry
            </p>
            <p>E-MAIL: kansanedustaja.janneheikkinen@gmail.com</p>
            <p>
              Mitä henkilötietoja käsitellään ja miksi? Käsittelemme seuraavia
              sinulta saamiamme henkilötietoja:
            </p>
            <p>
              Nimi
              <br />
              Yhteystiedot
              <br />
              Asuinalue <br />
              Osallistumishalukkuus vaalityöhön <br />
              Suostumus henkilötietojen käsittelyyn <br />
              Henkilötietoja käytämme Janne Heikkisen sekä hänen
              tukiyhdistyksensä Vapaa Pohjoinen ry:n viestintään sekä
              kampanjointi- ja markkinointitoimenpiteisiin.
            </p>
            <p>
              Käsitellyt henkilötiedot on kerätty sinulta itseltäsi, ja
              käsittelemme niitä antamasi suostumuksen perusteella.
            </p>
            <p>
              Kuka tietoja käsittelee ja siirretäänkö niitä EU:n tai Euroopan
              talousalueen ulkopuolelle? Henkilötietojasi käsittelee
              ensisijaisesti Janne Heikkinen, hänen kampanjansa aktiivit sekä
              Vapaa Pohjoinen ry:n toimijat. Lisäksi henkilötietoja voivat
              käsitellä Janne Heikkisen nettisivujen ylläpitoon osallistuvat
              henkilöt.
            </p>
            <p>
              Uutiskirjeiden lähettämisessä käytämme yhdysvaltalaista
              MailChimp-sähköpostipalvelua. Lisäksi henkilötietoja saatetaan
              väliaikaisesti käsitellä Googlen G Suite -palvelussa.
              Henkilötietojen siirto EU-alueelta Yhdysvaltoihin on sallittu
              sillä perusteella, että MailChimp ja Google ovat liittyneet mukaan
              EU-komission hyväksymään Privacy Shield-järjestelyyn. Lisätietoja
              MailChimpin tietosuojakäytännöistä saat täältä ja Googlen
              tietosuojakäytännöistä täältä.
            </p>
            <p>
              Kuinka kauan henkilötietoja säilytetään? Henkilötietojasi
              säilytetään enintään siihen asti, kunnes peruutat suostumuksesi
              niiden käsittelyyn. Suostumuksen peruuttamisen jälkeen
              henkilötiedot poistetaan mahdollisimman pian, kuitenkin
              viimeistään kuukauden kuluessa.
            </p>
            <p>Mitä oikeuksia sinulla on? Voit milloin tahansa pyytää meitä:</p>
            <p>
              vahvistamaan, käsittelemmekö sinua koskevia henkilötietoja, sekä
              pyytämään niistä kopion korjaamaan mahdolliset virheelliset
              henkilötietosi poistamaan henkilötietosi rajoittamaan
              henkilötietojesi käsittelyä Voit milloin tahansa peruuttaa
              uutiskirjeen klikkaamalla uutiskirjeen lopussa olevaa linkkiä.
              Muut tässä kohdassa tarkoitetut pyynnöt voit tehdä sähköpostitse
              osoitteeseen kansanedustaja.janneheikkinen@gmail.com
            </p>
            <p>
              Mikäli et ole tyytyväinen pyyntösi perusteella tekemäämme
              ratkaisuun tai olet sitä mieltä, että tietosuojaan liittyviä
              oikeuksiasi on loukattu, voit tehdä valituksen paikalliselle
              tietosuojaviranomaiselle. Suomessa tietosuojaviranomaisena toimii
              tietosuojavaltuutettu.
            </p>
            <p>
              Muutokset tähän tietosuojaselosteeseen Tätä tietosuojaselostetta
              voidaan päivittää aika ajoin esimerkiksi lainsäädännön muuttuessa.
              Tämä tietosuojaseloste on viimeksi päivitetty X.X.2022.
            </p>
          </div>
          <div className="modalActions">
            <div className="actionsContainer">
              <button
                className="acceptBtn"
                onClick={() => {
                  setIsAgreeing(true)
                  setIsOpen(false)
                }}
              >
                Accept
              </button>
              <button className="cancelBtn" onClick={() => setIsOpen(false)}>
                Back
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Modal
