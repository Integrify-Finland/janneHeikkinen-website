import React from "react";
import "./styles.scss"
import { navigateTo } from "gatsby-link";
import Recaptcha from "react-google-recaptcha";
import Button from "../Button"

const RECAPTCHA_KEY = process.env.SITE_RECAPTCHA_KEY;

function encode(data) {
  return Object.keys(data)
    .map(key => encodeURIComponent(key) + "=" + encodeURIComponent(data[key]))
    .join("&")
}

export default class ContactForm extends React.Component {
    constructor(props) {
    super(props)
    this.state = {}
    }

    handleChange = e => {
        this.setState({ [e.target.name]: e.target.value })
    }

    handleRecaptcha = value => {
        this.setState({ "g-recaptcha-response": value })
    }

    handleSubmit = e => {
    e.preventDefault()
    const form = e.target
    fetch("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: encode({
        "form-name": form.getAttribute("name"),
        ...this.state,
    }),
    })
        .then(() => navigateTo(form.getAttribute("action")))
        .catch(error => alert(error))
    }

    render() {
        return (
            <div className="contact-form__container">
                <form
                    name="contact-recaptcha"
                    method="post"
                    action="/thanks/"
                    data-netlify="true"
                    data-netlify-recaptcha="true"
                    onSubmit={this.handleSubmit}
                >
                <div className="contact-form__top">Lähetä viesti</div>
                {/* <noscript>
                        <p>This form won’t work with Javascript disabled</p>
                      </noscript> */}
                <p>
                    <label>
                    Nimesi (pakollinen)
                    <br />
                    <input
                        type="text"
                        name="name"
                        onChange={this.handleChange}
                        className="contact-form__input"
                    />
                    </label>
                </p>
                <p>
                    <label>
                    Sähköposti (pakollinen)
                    <br />
                    <input
                        type="email"
                        name="email"
                        onChange={this.handleChange}
                        className="contact-form__input"
                    />
                    </label>
                </p>
                <p>
                    <label>
                    Viestisi
                    <br />
                    <textarea
                        name="message"
                        onChange={this.handleChange}
                        className="contact-form__textarea"
                        rows="9"
                    />
                    </label>
                </p>
            {/* <Recaptcha
                ref="recaptcha"
                sitekey={RECAPTCHA_KEY}
                onChange={this.handleRecaptcha}
              /> */}
            <div>
                <Button variant="orange" size="md" label="Lähetä" />
            </div>
                </form>
        </div>
    )
    }
}

