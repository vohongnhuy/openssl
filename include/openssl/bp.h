/*
 * ====================================================================
 * Copyright 2015 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */
#ifndef HEADER_BP_H
# define HEADER_BP_H

# include <stdint.h>
# include "openssl/ec.h"
# include "openssl/bn.h"

# ifdef  __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# include <openssl/obj_mac.h>
# include <openssl/ec.h>
# include <openssl/bn.h>

/*
 * Convenient type to manipulate pairing groups.
 */
typedef struct bp_group_st BP_GROUP;

/*
 * Element from additive group G_1.
 */
typedef struct bp_g1_elem_st G1_ELEM;

/*
 * Element from additive group G_2.
 */
typedef struct bp_g2_elem_st G2_ELEM;

/*
 * Element from multiplicative target group G_T.
 */
typedef struct bp_gt_elem_st GT_ELEM;

/*
 * Functions for managing bilinear groups.
 */
BP_GROUP *BP_GROUP_new(void);
BP_GROUP *BP_GROUP_new_by_curve_name(int nid);
BP_GROUP *BP_GROUP_new_curve(const BIGNUM *p, const BIGNUM *a,
                             const BIGNUM *b, BN_CTX *ctx);
void BP_GROUP_free(BP_GROUP *group);
void BP_GROUP_clear_free(BP_GROUP *group);
int BP_GROUP_copy(BP_GROUP *dest, const BP_GROUP *src);
BP_GROUP *BP_GROUP_dup(const BP_GROUP *a);

/*
 *Functions for assigning parameters.
 */
# define NID_fp254bnb          1

int BP_GROUP_set_curve(BP_GROUP *group, const BIGNUM *p,
                       const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BP_GROUP_get_curve(const BP_GROUP *group, BIGNUM *p, BIGNUM *a,
                       BIGNUM *b, BN_CTX *ctx);
const EC_GROUP *BP_GROUP_get_group_G1(BP_GROUP *group);
int BP_GROUP_get_order(const BP_GROUP *group, BIGNUM *order, BN_CTX *ctx);
int BP_GROUP_set_param(BP_GROUP *group, BIGNUM *param);
int BP_GROUP_get_param(const BP_GROUP *group, BIGNUM *param);

/*
 * Generators and precomputation.
 */
int BP_GROUP_set_generator_G1(const BP_GROUP *group, G1_ELEM *g, BIGNUM *n);
int BP_GROUP_get_generator_G1(const BP_GROUP *group, G1_ELEM *g);
int BP_GROUP_precompute_mult_G1(BP_GROUP *group, BN_CTX *ctx);
int BP_GROUP_have_precompute_mult_G1(const BP_GROUP *group);
int BP_GROUP_get_generator_G2(const BP_GROUP *group, G2_ELEM *g);
int BP_GROUP_set_generator_G2(const BP_GROUP *group, G2_ELEM *g);
int BP_GROUP_precompute_mult_G2(BP_GROUP *group, BN_CTX *ctx);
int BP_GROUP_have_precompute_mult_G2(const BP_GROUP *group);

/*
 * Functions for manipulating G_1 elements.
 */
G1_ELEM *G1_ELEM_new(const BP_GROUP *group);
void G1_ELEM_free(G1_ELEM *a);
void G1_ELEM_clear_free(G1_ELEM *a);
int G1_ELEM_copy(G1_ELEM *a, const G1_ELEM *b);
G1_ELEM *G1_ELEM_dup(const G1_ELEM *a, const BP_GROUP *group);

/*
 * Functions for arithmetic in G_1.
 */
int G1_ELEM_set_to_infinity(const BP_GROUP *group, G1_ELEM *point);
int G1_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G1_ELEM *point, const BIGNUM *x,
                                        const BIGNUM *y,
                                        const BIGNUM *z, BN_CTX *ctx);
int G1_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G1_ELEM *point, BIGNUM *x,
                                        BIGNUM *y, BIGNUM *z,
                                        BN_CTX *ctx);
int G1_ELEM_set_affine_coordinates(const BP_GROUP *group, G1_ELEM *point,
                                   const BIGNUM *x, const BIGNUM *y,
                                   BN_CTX *ctx);
int G1_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G1_ELEM *point, BIGNUM *x, BIGNUM *y,
                                   BN_CTX *ctx);
int G1_ELEM_set_compressed_coordinates(const BP_GROUP *group, G1_ELEM *point,
                                       const BIGNUM *x, int y_bit,
                                       BN_CTX *ctx);
size_t G1_ELEM_point2oct(const BP_GROUP *group, const G1_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);
int G1_ELEM_oct2point(const BP_GROUP *group, const G1_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);
int G1_ELEM_add(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx);
int G1_ELEM_dbl(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *point,
                BN_CTX *ctx);
int G1_ELEM_invert(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx);
int G1_ELEM_is_at_infinity(const BP_GROUP *group, const G1_ELEM *point);
int G1_ELEM_is_on_curve(const BP_GROUP *group, const G1_ELEM *point,
                        BN_CTX *ctx);
int G1_ELEM_cmp(const BP_GROUP *group, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx);
int G1_ELEM_make_affine(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx);
int G1_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G1_ELEM *points[], BN_CTX *ctx);
int G1_ELEM_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *g_scalar,
                const G1_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);
int G1_ELEMs_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G1_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/*
 * Functions for manipulating G_2 elements.
 */
G2_ELEM *G2_ELEM_new(const BP_GROUP *group);
void G2_ELEM_free(G2_ELEM *point);
void G2_ELEM_clear_free(G2_ELEM *point);
int G2_ELEM_copy(G2_ELEM *point, const G2_ELEM *b);
G2_ELEM *G2_ELEM_dup(const G2_ELEM *point, const BP_GROUP *group);

int G2_ELEM_set_to_infinity(const BP_GROUP *group, G2_ELEM *point);
int G2_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G2_ELEM *point, const BIGNUM *x[2],
                                        const BIGNUM *y[2],
                                        const BIGNUM *z[2], BN_CTX *ctx);
int G2_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G2_ELEM *point, BIGNUM *x[2],
                                        BIGNUM *y[2], BIGNUM *z[2],
                                        BN_CTX *ctx);
int G2_ELEM_set_affine_coordinates(const BP_GROUP *group, G2_ELEM *point,
                                   const BIGNUM *x[2], const BIGNUM *y[2],
                                   BN_CTX *ctx);
int G2_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G2_ELEM *point, BIGNUM *x[2], BIGNUM *y[2],
                                   BN_CTX *ctx);
size_t G2_ELEM_point2oct(const BP_GROUP *group, const G2_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);
int G2_ELEM_oct2point(const BP_GROUP *group, G2_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);
int G2_ELEM_add(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                const G2_ELEM *b, BN_CTX *ctx);
int G2_ELEM_dbl(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                BN_CTX *ctx);
int G2_ELEM_invert(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);
int G2_ELEM_is_at_infinity(const BP_GROUP *group, const G2_ELEM *point);
int G2_ELEM_is_on_curve(const BP_GROUP *group, const G2_ELEM *point,
                        BN_CTX *ctx);
int G2_ELEM_cmp(const BP_GROUP *group, const G2_ELEM *point,
                const G2_ELEM *b, BN_CTX *ctx);
int G2_ELEM_make_affine(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);
int G2_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G2_ELEM *points[], BN_CTX *ctx);
int G2_ELEM_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *g_scalar,
                const G2_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);
int G2_ELEMs_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G2_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/*
 * Functions for manipulating G_T elements.
 */
GT_ELEM *GT_ELEM_new(const BP_GROUP *group);
void GT_ELEM_free(GT_ELEM *a);
void GT_clear_free(GT_ELEM *a);
int GT_ELEM_copy(GT_ELEM *a, const GT_ELEM *b);
GT_ELEM *GT_ELEM_dup(const GT_ELEM *a, const BP_GROUP *group);

/*
 * Functions for arithmetic in G_T.
 */
int GT_ELEM_zero(GT_ELEM *a);
int GT_ELEM_is_zero(GT_ELEM *a);
int GT_ELEM_set_to_unity(const BP_GROUP *group, GT_ELEM *a);
int GT_ELEM_is_unity(const BP_GROUP *group, const GT_ELEM *a);
int GT_ELEM_add(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_sub(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_sqr(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                BN_CTX *ctx);
int GT_ELEM_mul(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_inv(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, BN_CTX *ctx);
int GT_ELEM_cmp(const GT_ELEM *a, const GT_ELEM *b);
int GT_ELEM_exp(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a, const BIGNUM *b,
                BN_CTX *ctx);
size_t GT_ELEM_elem2oct(const BP_GROUP *group, const GT_ELEM *point,
                         unsigned char *buf, size_t len, BN_CTX *ctx);
int GT_ELEM_oct2elem(const BP_GROUP *group, GT_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/*
 * Pairing and multi-pairing computation.
 */
int GT_ELEM_pairing(const BP_GROUP *group, GT_ELEM *r, const G1_ELEM *p,
                    const G2_ELEM *q, BN_CTX *ctx);
int GT_ELEMs_pairing(const BP_GROUP *group, GT_ELEM *r, size_t num,
                     const G1_ELEM *p[], const G2_ELEM *q[], BN_CTX *ctx);

# ifdef  __cplusplus
}
# endif
#endif
