import React from "react"
import Img from "gatsby-image"

const Image = ({ fluid }) => {
  return (
    <Img
      fluid={fluid}
      style={{ maxWidth: `100%`, width: "150px", marginTop:"20px", border: "#6ccff6 2px solid" }}
    />
  )
}

export default Image
