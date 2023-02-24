import PropTypes from "prop-types"
import React from "react"
import "./styles.scss"

const Media = ({ name, birthday, text }) => {
  return (
    <div className="textbox">
      <h1>{name}</h1>
      <span>({birthday})</span>
      <p>{text}</p>
    </div>
  )
}

Media.propTypes = {
  name: PropTypes.string,
  birthday: PropTypes.string,
  text: PropTypes.string,
}

Media.defaultProps = {
  name: `Janne Heikkinen`,
  birthday: `s. 1990, Oulu`,
  text: `on kokoomuslainen kansanedustaja,yrittäjätaustainen yhteiskuntatieteiden maisteri ja kolmannen kauden 
  kaupunginvaltuutettu. Hän toimi aikaisemmin 
  Kempeleen kunnanvaltuuston puheenjohtajana ja toimii 
  tällä hetkellä kansanedustajana ja Oulun 
  kaupunginvaltuutettuna.`,
}

export default Media
