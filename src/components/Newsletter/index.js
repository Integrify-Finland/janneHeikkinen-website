import React, { useState } from "react"
import addToMailchimp from "gatsby-plugin-mailchimp"

import Button from "../Button"
import "./styles.scss"

const Newsletter = ({ animationStage, setAnimationStage }) => {
  const [email, setEmail] = useState("")
  const _handleChange = e => {
    const { value } = e.target
    setEmail(value)
  }

  const _handleSubmit = async e => {
    e.preventDefault()
    await addToMailchimp(email)
  }
  if (animationStage === "initial") {
    return (
      <>
        <div className="newsletter-container">
          <Button
            variant="orange"
            size="lg"
            label="tilaa uutiskirje→"
            onClick={() => setAnimationStage("first stage")}
          />
        </div>
      </>
    )
  } else if (animationStage === "first stage") {
    return (
      <div className="newsletter-container">
        <div className="newsletter-container--first-stage">
          <p className="newsletter-container--first-stage__text-top">
            Tilaa uutiskirje
          </p>
          <p className="newsletter-container--first-stage__text-bottom">
            Sähköposti:
          </p>
          <input
            className="newsletter-container--first-stage__input"
            name="email"
            onChange={_handleChange}
            type="email"
          ></input>
          <Button
            variant="primary"
            size="md"
            label="lähetä→"
            onClick={e => {
              _handleSubmit(e)
              setAnimationStage("second stage")
            }}
          />
        </div>
      </div>
    )
  } else {
    return (
      <div className="newsletter-container ">
        <div className="newsletter-container--second-stage">
          <p className="newsletter-container--second-stage__invisible-text">
            Kiitos paljon!
          </p>
        </div>
      </div>
    )
  }
}

export default Newsletter
