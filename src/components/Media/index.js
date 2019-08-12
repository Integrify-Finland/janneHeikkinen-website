
import PropTypes from "prop-types"
import React from "react"
import "./styles.scss"

const Media = ({ name, birthday, text }) => {
  

  return (
    <div className="textbox">
        <h1>{name}</h1><span>({birthday})</span>
        <p>{text}</p>
    </div>
  )
}

export default Media
