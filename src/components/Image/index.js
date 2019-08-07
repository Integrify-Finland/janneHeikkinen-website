import React from "react"
import Img from "gatsby-image"

const Image = ({ fluid }) => {
  return (
    <Img
      fluid={fluid}
      style={{ maxWidth: `100%`, width: "150px", marginTop:"20px", }}
    />
  )
}

export default Image
