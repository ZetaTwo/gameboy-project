meta:
    id: gbr1
    endian: le
    encoding: ascii
    title: GBR1 file
    application: GBMB
    file-extension:
      - gbm
seq:
    - id: magic
      contents: [0x47, 0x42, 0x4F, 0x31]
    - id: objects
      type: gbr1_object
      repeat: eos

types:
    gbr1_object:
        seq:
            - id: marker
              contents: [0x48, 0x50, 0x4a, 0x4d, 0x54, 0x4c]
            - id: object_type
              type: u2
            - id: object_id
              type: u2
            - id: master_id
              type: u2
            - id: crc
              type: u4
            - id: object_length
              type: u4
            - id: body
              size: object_length
