import React from "react"
import Img from "gatsby-image"

const Image = ({ fluid }) => {
  return (
    <Img
      fluid={fluid}
      style={{ maxWidth: `100%`, width: "300px", marginRight: "1rem" }}
    />
  )
}

export default Image
